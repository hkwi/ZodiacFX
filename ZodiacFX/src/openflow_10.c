/**
 * @file
 * openflow_10.c
 *
 * This file contains the OpenFlow v1.0 (0x01) specific functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2016 Northbound Networks.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Author: Paul Zanna <paul@northboundnetworks.com>
 *
 */

#include <asf.h>
#include <string.h>
#include <stdlib.h>
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "timers.h"
#include "of_helper.h"
#include "lwip/tcp.h"
#include "ipv4/lwip/ip.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"

#define OFPTT_ALL 0xff
#define OFPTT_EMERG 0xfe
#define OFP_MAX_TABLE_NAME_LEN 32

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int iLastFlow;
extern int OF_Version;

extern bool disable_ofp_pipeline;
extern char ofp_buffer[OFP_BUFFER_LEN];
extern struct controller controllers[MAX_CONTROLLERS];
extern struct fx_table_count fx_table_counts[MAX_TABLES];
extern struct fx_table_feature fx_table_features[MAX_TABLES];
extern struct fx_flow fx_flows[MAX_FLOWS];
extern struct fx_flow_timeout fx_flow_timeouts[MAX_FLOWS];
extern struct fx_flow_count fx_flow_counts[MAX_FLOWS];
extern uint32_t fx_buffer_id;
extern struct fx_packet_in fx_packet_ins[MAX_BUFFERS];
extern struct fx_switch_config fx_switch;
extern struct fx_port fx_ports[MAX_PORTS];
extern struct fx_port_count fx_port_counts[MAX_PORTS];
extern struct fx_group fx_groups[MAX_GROUPS];
extern struct fx_group_count fx_group_counts[MAX_GROUPS];
extern struct fx_group_bucket fx_group_buckets[MAX_GROUP_BUCKETS];
extern struct fx_group_bucket_count fx_group_bucket_counts[MAX_GROUP_BUCKETS];
extern struct fx_meter_band fx_meter_bands[MAX_METER_BANDS];

// fields are in host byte order
struct ofp10_filter {
	bool strict;
	uint8_t table_id;
	uint16_t priority;
	uint16_t out_port;
	struct ofp_match tuple;
};

static void send_ofp10_packet_in(struct ofp_packet_in base, struct fx_packet *packet, uint16_t max_len, uint8_t *send_bits){
	if(max_len > packet->length){
		max_len = packet->length;
	} // max_len is send_len
	
	uint16_t length = offsetof(struct ofp_packet_in, data) + max_len;
	base.header.length = htons(length);
	base.total_len = htons(packet->length);
	
	memset(ofp_buffer, 0, length);
	memcpy(ofp_buffer, &base, sizeof(struct ofp_packet_in));
	memcpy(ofp_buffer+offsetof(struct ofp_packet_in, data), packet->data, max_len);
	for(int i=0; i<MAX_CONTROLLERS; i++){
		struct ofp_pcb *ofp = &(controllers[i].ofp);
		if((*send_bits & (1<<i)) == 0 ){
			continue;
		}
		if(!ofp->negotiated){
			*send_bits &= ~(1<<i);
			continue;
		}
		if(ofp_tx_room(ofp) < length){
			continue;
		}
		uint32_t xid = htonl(ofp->xid++);
		memcpy(ofp_buffer+4, &xid, 4);
		ofp_tx_write(ofp, ofp_buffer, length);
		*send_bits &= ~(1<<i);
	}
}

/*
 * scans flow table for matching flow
 */
static int filter_ofp10_flow(int first, struct ofp10_filter filter){
	uint8_t table_id = filter.table_id;
	if(table_id == OFPTT_EMERG){
		table_id = 1;
	}
	for(int i=first; i<iLastFlow; i++){
		if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0){
			continue;
		}
		if (table_id != 0xff && table_id != fx_flows[i].table_id){
			continue;
		}
		if(filter.strict){
			if (filter.priority != fx_flows[i].priority){
				continue;
			}
			if(memcmp(&fx_flows[i].tuple, &filter.tuple, sizeof(struct ofp_match))!=0){
				continue;
			}
		} else {
			if(field_match10(&fx_flows[i].tuple, &filter.tuple) == false){
				continue;
			}
		}
		if (filter.out_port != OFPP_NONE){
			bool out_port_match = false;
			uintptr_t ops = (uintptr_t)fx_flows[i].ops;
			while(ops < (uintptr_t)fx_flows[i].ops + fx_flows[i].ops_length){
				struct ofp_action_header action;
				memcpy(&action, (void*)ops, sizeof(action));
				if(action.type==htons(OFPAT10_OUTPUT)){
					struct ofp_action_output output;
					memcpy(&output, (void*)ops, sizeof(output));
					if (ntohs(output.port) == filter.out_port){
						out_port_match = true;
					}
				}
				ops += ntohs(action.len);
			}
			if(out_port_match==false){
				continue;
			}
		}
		return i;
	}
	return -1;
}

static bool push_vlan(struct fx_packet *packet){
	uint8_t *data = packet->data;
	uint16_t length = packet->length + 4;
	if(length > packet->capacity){
		if(packet->malloced){
			data = realloc(packet->data, length);
		}else{
			data = malloc(length);
		}
		if(data == NULL){
			return false;
		}
		packet->malloced = true;
		packet->capacity = length;
	}
	memmove(data, packet->data, 12);
	memmove(data+16, packet->data+12, packet->length-12);
	data[12] = 0x81;
	data[13] = 0x00;
	packet->data = data;
	packet->length = length;
	return true;
}

/*
 *	return false on fatal status
 */
static bool execute_ofp10_action(struct fx_packet *packet, struct fx_packet_oob *oob, void *action, int flow){
	struct ofp13_action_header act;
	memcpy(&act, action, sizeof(act));
	
	switch(ntohs(act.type)){
		case OFPAT10_OUTPUT:
		{
			struct ofp_action_output out;
			memcpy(&out, action, sizeof(out));
			
			uint16_t in_port = packet->in_port;
			uint32_t out_port_idx = ntohs(out.port) - 1; // port starts from 1
			if(out_port_idx < OFPP_MAX){
				if(out.port != in_port && out_port_idx<MAX_PORTS && Zodiac_Config.of_port[out_port_idx]==PORT_OPENFLOW){
					if(disable_ofp_pipeline == false){
						fx_port_counts[out_port_idx].tx_packets++;
						gmac_write(packet->data, packet->length, 1<<out_port_idx);
					}
				}
			}else if(out.port == htons(OFPP_IN_PORT)){
				if(out.port != in_port && out_port_idx<MAX_PORTS && Zodiac_Config.of_port[out_port_idx]==PORT_OPENFLOW){
					if(disable_ofp_pipeline == false){
						fx_port_counts[out_port_idx].tx_packets++;
						gmac_write(packet->data, packet->length, 1<<out_port_idx);
					}
				}
			}else if(out.port == htons(OFPP_ALL) || out.port == htons(OFPP_FLOOD) || out.port == htons(OFPP_NORMAL)){
				if(disable_ofp_pipeline == false){
					uint8_t p = 0;
					for(uint32_t i=0; i<MAX_PORTS; i++){
						if(Zodiac_Config.of_port[i]==PORT_OPENFLOW && i != ntohs(in_port)-1){
							p |= 1<<i;
							fx_port_counts[i].tx_packets++;
						}
					}
					if(p != 0){
						gmac_write(packet->data, packet->length, p);
					}
				}
			}else if(out.port == htons(OFPP_CONTROLLER)){
				uint8_t send_bits = 0x80;
				uint32_t buffer_id = htonl(fx_buffer_id++);
				uint8_t reason = OFPR_ACTION;
				
				struct ofp_packet_in msg = {
					.header = {
						.version = 1,
						.type = OFPT10_PACKET_IN,
					},
					.buffer_id = buffer_id,
					.in_port = packet->in_port,
					.total_len = htons(packet->length),
					.reason = reason,
				};
				for(int i=0; i<MAX_CONTROLLERS; i++){
					if(controllers[i].ofp.negotiated){
						send_bits |= 1<<i;
					}
				}
				send_ofp10_packet_in(msg, packet, ntohs(out.max_len), &send_bits);
				if(send_bits != 0){
					for(int i=0; i<MAX_BUFFERS; i++){
						struct fx_packet_in *pin = fx_packet_ins+i;
						if(pin->send_bits == 0){
							void *data = malloc(packet->length);
							if(data != NULL){
								memcpy(data, packet->data, packet->length);
								
								pin->buffer_id = msg.buffer_id;
								pin->reason = msg.reason;
								pin->send_bits = send_bits;
								pin->valid_until = sys_get_ms() + BUFFER_TIMEOUT;
								
								struct fx_packet pkt = {
									.data = data,
									.capacity = packet->length,
									.length = packet->length,
									.malloced = true,
									.in_port = packet->in_port,
									.metadata = packet->metadata,
									.tunnel_id = packet->tunnel_id,
									.in_phy_port = packet->in_phy_port,
								};
								pin->packet = pkt;
								
								pin->max_len = ntohs(out.max_len);
							}
							break;
						}
					}
				}
			} // xxx: OFPP10_TABLE
		}
		break;
		
		case OFPAT10_SET_VLAN_VID:
		{
			struct ofp_action_vlan_vid avid;
			memcpy(&avid, action, sizeof(avid));
			
			if((oob->vlan[0] & 0x10) == 0){ // CFI bit for tag presence
				if(push_vlan(packet) == false){
					return false;
				}
			}
			if(avid.vlan_vid == htons(0xffff)){
				packet->data[14] &= 0xF0;
				packet->data[15] = 0;
			}else{
				uint8_t vlan[2];
				memcpy(vlan, &avid.vlan_vid, 2);
				packet->data[14] &= 0xF0;
				packet->data[14] |= vlan[0] & 0x0F;
				packet->data[15] = vlan[1];
			}
			sync_oob(packet, oob);
		}
		break;
		
		case OFPAT10_SET_VLAN_PCP:
		{
			struct ofp_action_vlan_pcp pcp;
			memcpy(&pcp, action, sizeof(pcp));
			
			if((oob->vlan[0] & 0x10) == 0){ // CFI bit for tag presence
				if(push_vlan(packet) == false){
					return false;
				}
			}
			packet->data[14] &= 0x0F;
			packet->data[14] |= (pcp.vlan_pcp<<5);
			sync_oob(packet, oob);
		}
		break;
		
		case OFPAT10_STRIP_VLAN:
		if((oob->vlan[0] & 0x10) == 0){ // CFI bit for tag presence
			packet->length -= 4;
			memmove(packet->data+12, packet->data+16, packet->length-12);
			sync_oob(packet, oob);
		}
		break;
		
		case OFPAT10_SET_DL_SRC:
		{
			struct ofp_action_dl_addr dl;
			memcpy(&dl, action, sizeof(dl));
			memcpy(packet->data, dl.dl_addr, OFP10_ETH_ALEN);
		}
		break;
		
		case OFPAT10_SET_DL_DST:
		{
			struct ofp_action_dl_addr dl;
			memcpy(&dl, action, sizeof(dl));
			memcpy(packet->data+OFP10_ETH_ALEN, dl.dl_addr, OFP10_ETH_ALEN);
		}
		break;
		
		case OFPAT10_SET_NW_SRC:
		if(memcmp(packet->data+oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
			struct ofp_action_nw_addr nw;
			memcpy(&nw, action, sizeof(nw));
			
			struct ip_hdr *iphdr = (void*)(packet->data+oob->eth_type_offset+2);
			memcpy(&iphdr->src.addr, &nw.nw_addr, 4);
		}
		break;
		
		case OFPAT10_SET_NW_DST:
		if(memcmp(packet->data+oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
			struct ofp_action_nw_addr nw;
			memcpy(&nw, action, sizeof(nw));
			
			struct ip_hdr *iphdr = (void*)(packet->data+oob->eth_type_offset+2);
			memcpy(&iphdr->dest.addr, &nw.nw_addr, 4);
		}
		break;
		
		case OFPAT10_SET_NW_TOS:
		if(memcmp(packet->data+oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
			struct ofp_action_nw_tos tos;
			memcpy(&tos, action, sizeof(tos));
			
			struct ip_hdr *iphdr = (void*)(packet->data+oob->eth_type_offset+2);
			IPH_TOS_SET(iphdr, tos.nw_tos);
		}
		break;
		
		case OFPAT10_SET_TP_SRC:
		if(memcmp(packet->data+oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
			struct ofp_action_tp_port tp;
			memcpy(&tp, action, sizeof(tp));
			
			struct ip_hdr *iphdr = (void*)(packet->data+oob->eth_type_offset+2);
			if(IPH_PROTO(iphdr) == IP_PROTO_TCP){
				struct tcp_hdr *tcphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
				memcpy(&tcphdr->src, &tp.tp_port, 2);
			}else if(IPH_PROTO(iphdr) == IP_PROTO_UDP){
				struct udp_hdr *udphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
				memcpy(&udphdr->src, &tp.tp_port, 2);
			}
		}
		break;

		case OFPAT10_SET_TP_DST:
		if(memcmp(packet->data+oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
			struct ofp_action_tp_port tp;
			memcpy(&tp, action, sizeof(tp));
			
			struct ip_hdr *iphdr = (void*)(packet->data+oob->eth_type_offset+2);
			if(IPH_PROTO(iphdr) == IP_PROTO_TCP){
				struct tcp_hdr *tcphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
				memcpy(&tcphdr->dest, &tp.tp_port, 2);
			}else if(IPH_PROTO(iphdr) == IP_PROTO_UDP){
				struct udp_hdr *udphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
				memcpy(&udphdr->dest, &tp.tp_port, 2);
			}
		}
		break;
		
		// TODO: OFPAT_ENQUEUE
	}
	return true;
}

static enum ofp_pcb_status add_ofp10_flow(struct ofp_pcb *self, void *ops, uint16_t ops_len){
	struct ofp_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp_flow_mod), self->rskip);
	uint16_t length = ntohs(hint.header.length);
	
	uint8_t table_id = 0;
	if((hint.flags & htons(OFPFF_EMERG)) != 0){
		table_id = 1;
	}
	if((hint.flags & htons(OFPFF_CHECK_OVERLAP)) != 0){
		int overlap = -1;
		for(int i=0; i<iLastFlow; i++){
			if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0
					|| table_id != fx_flows[i].table_id
					|| ntohs(hint.priority) != fx_flows[i].priority){
				continue;
			}
			if(field_match10(&hint.match, &fx_flows[i].tuple) != 1){
				overlap = i;
				break;
			}
			if(field_match10(&fx_flows[i].tuple, &hint.match) != 1){
				overlap = i;
				break;
			}
		}
		if(overlap >= 0){
			if(ops != NULL) free(ops);
			return ofp_write_error(self, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_OVERLAP);
		}
	}

	struct ofp10_filter filter = {
		.strict = true,
		.table_id = table_id,
		.priority = ntohs(hint.priority),
		.out_port = OFPP_NONE,
		.tuple = hint.match,
	};
	int found = filter_ofp10_flow(0, filter);
	int n = found;
	if(n < 0){
		for(int i=0; i<iLastFlow; i++){
			if(fx_flows[i].send_bits == 0){
				n = i;
				break;
			}
		}
	}
	if(n < 0){
		if(iLastFlow >= MAX_FLOWS){
			if(ops != NULL) free(ops);
			return ofp_write_error(self, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_ALL_TABLES_FULL);
		}else{
			n = iLastFlow++;
		}
	}
	fx_flows[n].send_bits = FX_FLOW_ACTIVE;
	fx_flows[n].table_id = table_id;
	fx_flows[n].priority = ntohs(hint.priority);
	fx_flows[n].flags = ntohs(hint.flags);
	fx_flows[n].oxm = NULL;
	fx_flows[n].oxm_length = 0;
	if(fx_flows[n].ops != NULL){
		free(fx_flows[n].ops);
	}
	fx_flows[n].ops = ops;
	fx_flows[n].ops_length = ops_len;
	memcpy(&fx_flows[n].tuple, &hint.match, sizeof(struct ofp_match));
	
	fx_flow_timeouts[n].hard_timeout = ntohs(hint.hard_timeout);
	fx_flow_timeouts[n].idle_timeout = ntohs(hint.idle_timeout);
	fx_flow_timeouts[n].init = sys_get_ms64();
	fx_flow_timeouts[n].update = sys_get_ms();
	
	if(found < 0){
		fx_flow_counts[n].byte_count = 0;
		fx_flow_counts[n].packet_count = 0;
	}
	if(hint.buffer_id != htonl(-1)){
		// TODO: enqueue buffer
	}
	self->rskip += length;
	return OFP_OK;
}

static enum ofp_pcb_status modify_ofp10_flow(struct ofp_pcb *self, void *ops, uint16_t ops_len, bool strict){
	struct ofp_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp_flow_mod), self->rskip);
	uint16_t length = ntohs(hint.header.length);
	
	uint8_t table_id = 0;
	if((hint.flags & htons(OFPFF_EMERG)) != 0){
		table_id = 1;
	}
	struct ofp10_filter filter = {
		.strict = strict,
		.table_id = table_id,
		.priority = ntohs(hint.priority),
		.out_port = OFPP_NONE,
		.tuple = hint.match,
	};

	// We'll copy ops per flow entry.
	int count = 0;
	for(int i=filter_ofp10_flow(0, filter); i>=0; i=filter_ofp10_flow(i+1, filter)){
		count++;
	}
	void **tmp = malloc(count*sizeof(char*));
	for(int i=0; i<count; i++){
		tmp[i] = malloc(ops_len);
		if(tmp[i]==NULL){
			for(int j=0; j<i; j++){
				free(tmp[j]);
			}
			if(ops != NULL) free(ops);
			return ofp_write_error(self, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_EPERM);
		}
	}
	for(int i=filter_ofp10_flow(0, filter); i>=0; i=filter_ofp10_flow(i+1, filter)){
		if(fx_flows[i].ops != NULL){
			free(fx_flows[i].ops);
		}
		void *flow_ops = tmp[--count];
		memcpy(flow_ops, ops, ops_len);
		fx_flows[i].ops = flow_ops;
		fx_flows[i].ops_length = ops_len;
	}
	if(ops != NULL) free(ops);
	free(tmp);
	if(hint.buffer_id != htonl(-1)){
		// TODO: enqueue buffer
	}
	self->rskip += length;
	return OFP_OK;
}

static enum ofp_pcb_status delete_ofp10_flow(struct ofp_pcb *self, void *ops, uint16_t ops_len, bool strict){
	struct ofp_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(hint), self->rskip);
	uint16_t length = ntohs(hint.header.length);
	
	uint8_t table_id = 0;
	if((hint.flags & htons(OFPFF_EMERG)) != 0){
		table_id = 1;
	}
	struct ofp10_filter filter = {
		.strict = strict,
		.table_id = table_id,
		.priority = ntohs(hint.priority),
		.out_port = ntohs(hint.out_port),
	};
	memcpy(&filter.tuple, &hint.match, sizeof(struct ofp_match));

	for(int i=filter_ofp10_flow(0, filter); i>=0; i=filter_ofp10_flow(i+1, filter)){
		if((fx_flows[i].flags & OFPFF_SEND_FLOW_REM) != 0){
			uint8_t send_bits = 0;
			for(int j=0; j<MAX_CONTROLLERS; j++){
				send_bits |= 1<<j;
			}
			fx_flows[i].send_bits = send_bits;
			fx_flows[i].reason = OFPRR_DELETE;
		} else {
			if(fx_flows[i].oxm != NULL){
				free(fx_flows[i].oxm);
			}
			if(fx_flows[i].ops != NULL){
				free(fx_flows[i].ops);
			}
			memset(fx_flows+i, 0, sizeof(struct fx_flow));
		}
	}
	if(ops != NULL) free(ops);
	self->rskip += length;
	return 0;
}

/*
 * context : ofp_buffer is filled by request heading 64 bytes or less
 */
static enum ofp_pcb_status mod_ofp10_flow(struct ofp_pcb *self, void *ops, uint16_t ops_len){
	struct ofp_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp_flow_mod), self->rskip);
	switch(ntohs(hint.command)){
		case OFPFC_ADD:
			return add_ofp10_flow(self, ops, ops_len);
		
		case OFPFC_MODIFY:
			return modify_ofp10_flow(self, ops, ops_len, false);
		
		case OFPFC_MODIFY_STRICT:
			return modify_ofp10_flow(self, ops, ops_len, true);
		
		case OFPFC_DELETE:
			return delete_ofp10_flow(self, ops, ops_len, false);
		
		case OFPFC_DELETE_STRICT:
			return delete_ofp10_flow(self, ops, ops_len, true);
		
		default:
			return ofp_write_error(self, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_BAD_COMMAND);
	}
}

static uint16_t fill_ofp10_flow_stats(const struct ofp_flow_stats_request *req, int *mp_index, void *buffer, uint16_t capacity){
	uint8_t table_id = req->table_id;
	if(table_id == OFPTT_EMERG){
		table_id = 1;
	}
	struct ofp10_filter filter = {
		.out_port = req->out_port,
		.table_id = table_id,
	};
	memcpy(&filter.tuple, &req->match, sizeof(struct ofp_match));

	uint16_t length = 0;
	bool complete = true;
	for(int i=filter_ofp10_flow(*mp_index, filter); i>=0; i=filter_ofp10_flow(i+1, filter)){
		// ofp_flow_stats fixed fields are the same length with ofp_flow_mod
		*mp_index = i; // we want to revisit k.
		if(length + offsetof(struct ofp_flow_stats, actions) + fx_flows[i].ops_length > capacity){
			complete = false;
			break;
		}
		uint64_t duration = sys_get_ms64() - fx_flow_timeouts[i].init;
		table_id = fx_flows[i].table_id;
		if(table_id == 1){
			table_id = OFPTT_EMERG;
		}
		struct ofp_flow_stats stats = {
			.length = htons(offsetof(struct ofp_flow_stats, actions)+fx_flows[i].ops_length),
			.table_id = table_id,
			.match = fx_flows[i].tuple,
			.duration_sec = htonl(duration/1000U),
			.duration_nsec = htonl((duration%1000U)*1000000U),
			.priority = htons(fx_flows[i].priority),
			.idle_timeout = htons(fx_flow_timeouts[i].idle_timeout),
			.hard_timeout = htons(fx_flow_timeouts[i].hard_timeout),
			.cookie = fx_flows[i].cookie,
			.packet_count = htonll(fx_flow_counts[i].packet_count),
			.byte_count = htonll(fx_flow_counts[i].byte_count),
		};
		uintptr_t buf = (uintptr_t)buffer + length;
		// struct ofp_flow_stats
		memcpy((void*)buf, &stats, sizeof(struct ofp_flow_stats));
		// actions
		int len = offsetof(struct ofp_flow_stats, actions);
		buf = (uintptr_t)buffer + length + len;
		memcpy((void*)buf, fx_flows[i].ops, fx_flows[i].ops_length);
		length += len + fx_flows[i].ops_length;
	}
	if(complete){
		*mp_index = -1; // complete
	}
	return length;
}

static uint16_t fill_ofp10_aggregate_stats(const struct ofp_aggregate_stats_request *req, int *mp_index, void *buffer, uint16_t capacity){
	if(capacity < 24){
		return 0;
	}
	struct ofp10_filter filter = {
		.table_id = req->table_id,
		.out_port = req->out_port,
	};
	memcpy(&filter.tuple, &req->match, sizeof(struct ofp_match));

	struct ofp_aggregate_stats_reply res = {0};
	for(int i=filter_ofp10_flow(*mp_index, filter); i>=0; i=filter_ofp10_flow(i+1, filter)){
		res.packet_count += fx_flow_counts[i].packet_count;
		res.byte_count += fx_flow_counts[i].byte_count;
		res.flow_count++;
	}
	memcpy(buffer, &res, 24);
	*mp_index = -1;
	return 24;
}

static uint16_t fill_ofp10_table_stats(int *mp_index, void *buffer, uint16_t capacity){
	if(capacity < 24){
		return 0;
	}
	bool complete = true;
	uint16_t length = 0;
	for(int i=*mp_index; i<2; i++){
		*mp_index = i;
		if(length+24 > capacity){
			complete = false;
			break;
		}
		uint32_t active = 0;
		for(int j=0; j<iLastFlow; j++){
			if((fx_flows[j].send_bits & FX_FLOW_ACTIVE) != 0
					&& fx_flows[j].table_id == i){
				active++;
			}
		}
		uint8_t table_id = 0;
		if(i == 1){
			table_id = OFPTT_EMERG;
		}
		struct ofp_table_stats stat = {
			.table_id = table_id,
			.wildcards = htonl(OFPFW_ALL),
			.max_entries = fx_table_features[i].max_entries,
			.active_count = htonl(active),
			.matched_count = htonll(fx_table_counts[i].matched),
			.lookup_count = htonll(fx_table_counts[i].lookup),
		};
		memcpy(stat.name, fx_table_features[i].name, OFP_MAX_TABLE_NAME_LEN);
		
		uintptr_t buf = (uintptr_t)buffer+length;
		memcpy((void*)buf, &stat, sizeof(stat));
		length += sizeof(stat);
	}
	if(complete){
		*mp_index = -1;
	}
	return length;
}

static void make_port_stats(uint16_t i, struct ofp10_port_stats *stats){
	sync_switch_port_counts(i);
	stats->port_no = htons(i+1);
	stats->rx_packets = htonll(fx_port_counts[i].rx_packets);
	stats->tx_packets = htonll(fx_port_counts[i].tx_packets);
	stats->rx_bytes = htonll(fx_port_counts[i].rx_bytes);
	stats->tx_bytes = htonll(fx_port_counts[i].tx_bytes);
	stats->rx_dropped = htonll(fx_port_counts[i].rx_dropped);
	stats->tx_dropped = htonll(fx_port_counts[i].tx_dropped);
	stats->rx_errors = htonll(fx_port_counts[i].rx_errors);
	stats->tx_errors = htonll(fx_port_counts[i].tx_errors);
	stats->rx_frame_err = htonll(fx_port_counts[i].rx_frame_err);
	stats->rx_over_err = htonll(fx_port_counts[i].rx_over_err);
	stats->rx_crc_err = htonll(fx_port_counts[i].rx_crc_err);
	stats->collisions = htonll(fx_port_counts[i].collisions);
}

/*
 *	@param port in network byte order
 */
static uint16_t fill_ofp10_port_stats(uint16_t port, int *mp_index, void *buffer, uint16_t capacity){
	struct ofp10_port_stats stat;
	uint16_t port_index = ntohs(port)-1;
	if(port == htons(OFPP_NONE)){
		bool complete = true;
		uint16_t len = 0;
		for(int i=*mp_index; i<MAX_PORTS; i++){
			if(Zodiac_Config.of_port[i] == PORT_OPENFLOW){
				*mp_index=i;
				if(len + sizeof(stat) > capacity){
					complete = false;
					break;
				}
				make_port_stats(i, &stat);
				memcpy((void*)((uintptr_t)buffer + len), &stat, sizeof(stat));
				len += sizeof(stat);
			}
		}
		if(complete){
			*mp_index = -1;
		}
		return len;
	}else if(port_index < MAX_PORTS){
		make_port_stats(port_index, &stat);
		memcpy(buffer, &stat, sizeof(stat));
		*mp_index = -1;
		return sizeof(stat);
	}
	*mp_index = -1;
	return 0;
}

static enum ofp_pcb_status ofp10_write_mp_error(struct ofp_pcb *self, uint16_t ofpet, uint16_t ofpec){
	struct ofp_stats_request mpreq;
	memcpy(&mpreq, self->mpreq_hdr, sizeof(mpreq));
	uint16_t length = ntohs(mpreq.header.length);
	
	if(self->mpreq_pos + ofp_rx_length(self) < length || ofp_tx_room(self) < 12+12){
		return OFP_NOOP;
	}
	uint16_t remaining = length - self->mpreq_pos;
	self->rskip += remaining;
	self->mpreq_pos += remaining;
	
	struct ofp_error_msg err = {
		.header = {
			.version = 4,
			.type = OFPT10_ERROR,
			.length = htons(24),
			.xid = mpreq.header.xid,
		},
		.type = htons(ofpet),
		.code = htons(ofpec),
	};
	memcpy(ofp_buffer, &err, 12);
	memcpy(ofp_buffer+12, self->mpreq_hdr, 12);
	ofp_tx_write(self, ofp_buffer, 12+12);

	self->mpreq_pos = 0;
	self->mpreq_on = false;
	return OFP_OK;
}

enum ofp_pcb_status ofp10_multipart_complete(struct ofp_pcb *self){
	struct ofp_stats_request mpreq;
	struct ofp10_stats_reply mpres;
	memcpy(&mpreq, self->mpreq_hdr, sizeof(mpreq));
	memcpy(&mpres, self->mpreq_hdr, sizeof(mpres));
	mpres.header.type = OFPT10_STATS_REPLY;
	uint16_t length = ntohs(mpreq.header.length);

	while(self->mpreq_pos != 0){
		switch(ntohs(mpreq.type)){
			case OFPST_DESC:
			if(ofp_tx_room(self) < 12+1056){
				return OFP_NOOP;
			}else if(length > 12){ // has no body in request
				return ofp10_write_mp_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
			}else{
				mpres.header.length = htons(12+1056);
				mpres.flags = 0;
				struct ofp_desc_stats zodiac_desc = {
					.mfr_desc = "Northbound Networks",
					.hw_desc  = "Zodiac-FX Rev.A",
					.sw_desc  = VERSION,
					.serial_num= "",
					.dp_desc  = "World's smallest OpenFlow switch!"
				};
				memcpy(ofp_buffer, &mpres, sizeof(mpres));
				memcpy(ofp_buffer+16, &zodiac_desc, 1056);
				ofp_tx_write(self, ofp_buffer, 12+1056);
			}
			break;
			
			case OFPST_FLOW:
			if(ofp_rx_length(self) < 44){ // sizeof(struct ofp_flow_stats_request)
				return OFP_NOOP;
			}else{
				struct ofp_flow_stats_request hint;
				if(self->mp_out_index < 0){
					pbuf_copy_partial(self->rbuf, &hint, sizeof(hint), self->rskip);
					self->mpreq_pos += ofp_rx_read(self, self->mp_in, sizeof(hint));
					self->mp_out_index = 0;
				} else {
					// restore hint
					memcpy(&hint, self->mp_in, sizeof(hint));
				}
				
				uint16_t capacity = ofp_tx_room(self);
				if(capacity > OFP_BUFFER_LEN){
					capacity = OFP_BUFFER_LEN;
				}
				uint16_t unitlength = fill_ofp10_flow_stats(&hint,
					&self->mp_out_index, ofp_buffer+12, capacity-12);
				mpres.flags = htons(OFPSF_REPLY_MORE);
				if(self->mp_out_index < 0){
					mpres.flags = 0;
				}
				mpres.header.length = htons(12+unitlength);
				memcpy(ofp_buffer, &mpres, 12);
				ofp_tx_write(self, ofp_buffer, 12+unitlength);
			}
			break;

			case OFPST_AGGREGATE:
			if(ofp_rx_length(self) < 44){
				return OFP_NOOP;
			}else{
				struct ofp_aggregate_stats_request hint; // sizeof(hint)==44
				if(self->mp_out_index < 0){
					pbuf_copy_partial(self->rbuf, &hint, 44, self->rskip);
					self->mpreq_pos += ofp_rx_read(self, self->mp_in, 44);
					self->mp_out_index = 0;
				} else {
					// restore
					memcpy(&hint, self->mp_in, 40);
				}
				
				uint16_t capacity = ofp_tx_room(self);
				if(capacity > OFP_BUFFER_LEN){
					capacity = OFP_BUFFER_LEN;
				}
				uint16_t unitlength = fill_ofp10_aggregate_stats(&hint,
					&self->mp_out_index, ofp_buffer+12, capacity-12);
				if(unitlength == 0){
					return OFP_NOOP;
				}
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPSF_REPLY_MORE);
				}
				mpres.header.length = htons(16+unitlength);
				memcpy(ofp_buffer, &mpres, 16);
				ofp_tx_write(self, ofp_buffer, 16+unitlength);
			}
			break;

			case OFPST_TABLE:
			if(ofp_tx_room(self) < 12+64){
				return OFP_NOOP;
			} else {
				if(self->mp_out_index < 0){
					self->mp_out_index = 0;
				}
				uint16_t capacity = ofp_tx_room(self);
				if(capacity > OFP_BUFFER_LEN){
					capacity = OFP_BUFFER_LEN;
				}
				uint16_t unitlength = fill_ofp10_table_stats(
					&self->mp_out_index, ofp_buffer+12, capacity-12);
				if(unitlength==0){
					return OFP_NOOP;
				}
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPSF_REPLY_MORE);
				}
				mpres.header.length = htons(12+unitlength);
				memcpy(ofp_buffer, &mpres, 12);
				ofp_tx_write(self, ofp_buffer, 12+unitlength);
			}
			break;

			case OFPST_PORT:
			// 8 = sizeof(struct ofp_port_stats_request)
			// 104 = sizeof(struct ofp_port_stats)
			if(ofp_rx_length(self) < 8 || ofp_tx_room(self) < 12+104){
				return OFP_NOOP;
			}else{
				if(self->mp_out_index < 0){
					self->mp_out_index = 0;
				}
				if(length != 12+8){
					return ofp10_write_mp_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
				}
				struct ofp10_port_stats_request hint;
				self->mpreq_pos += ofp_rx_read(self, &hint, 8);
				
				uint16_t capacity = ofp_tx_room(self);
				if(capacity > OFP_BUFFER_LEN){
					capacity = OFP_BUFFER_LEN;
				}
				uint16_t unitlength = fill_ofp10_port_stats(hint.port_no,
					&self->mp_out_index, ofp_buffer+12, capacity-12);
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPSF_REPLY_MORE);
				}
				mpres.header.length = htons(12+unitlength);
				memcpy(ofp_buffer, &mpres, 12);
				ofp_tx_write(self, ofp_buffer, 12+unitlength);
			}
			break;
			
			// TODO: OFPST_QUEUE
			
			default:
			{
				if(ofp_rx_length(self) < length-16 || ofp_tx_room(self) < 12+64){
					return OFP_NOOP;
				}
				memcpy(ofp_buffer, self->mpreq_hdr, 16);
				self->mpreq_pos += ofp_rx_read(self, ofp_buffer+16, length-16);
				mpres.flags = 0;
				
				uint16_t tail = length;
				if (tail > 64){
					tail = 64;
				}
				char reply[12+64];
				struct ofp_error_msg err = {
					.header = {
						.version = mpreq.header.version,
						.type = OFPT13_ERROR,
						.length = htons(12+tail),
						.xid = mpreq.header.xid,
					},
					.type = htons(OFPET10_BAD_REQUEST),
					.code = htons(OFPBRC10_BAD_STAT),
				};
				memcpy(reply, &err, 12);
				memcpy(reply+12, ofp_buffer, tail);
				ofp_tx_write(self, reply, 12+tail);
			}
			break;
		}
		if (self->mpreq_pos >= length && (ntohs(mpres.flags) & OFPSF_REPLY_MORE) == 0){
			self->mpreq_pos = 0;
			self->mpreq_on = false; // OFPSF_REQ_MORE not defined in spec.
		}
	}
	return OFP_OK;
}

enum ofp_pcb_status ofp10_handle(struct ofp_pcb *self){
	if(ofp_rx_length(self) < 8){
		return OFP_NOOP;
	};
	struct ofp_header req; // look ahead
	pbuf_copy_partial(self->rbuf, &req, 8, self->rskip);
	uint16_t length = ntohs(req.length);
	
	uint16_t head = self->rskip;
	enum ofp_pcb_status ret = OFP_NOOP;
	switch(req.type){
		/*
		 * functions here must follow:
		 * - do not vacuum ofp_pcb.rbuf
		 * - may directly return by ofp_write_error
		 * - process single openflow message
		 */
		
		case OFPT10_FEATURES_REQUEST:
		if(ofp_tx_room(self) < offsetof(struct ofp10_switch_features, ports)+sizeof(struct ofp10_phy_port)*MAX_PORTS){
			// noop
		} else if(length > 8){
			return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
		} else {
			uint16_t len = offsetof(struct ofp10_switch_features, ports);
			for(int i=0; i<MAX_PORTS; i++){
				struct ofp10_phy_port port = {
					.port_no = htons(i+1),
					.config = htonl(get_switch_config(i)),
					.state = htonl(get_switch_status(i)),
					.curr = htonl(get_switch_ofppf10_curr(i)),
					.advertised = htonl(get_switch_ofppf10_advertised(i)),
					.supported = htonl(	OFPPF10_COPPER | OFPPF10_PAUSE | OFPPF10_PAUSE_ASYM |OFPPF10_100MB_FD \
					| OFPPF10_100MB_HD | OFPPF10_10MB_FD | OFPPF10_10MB_HD | OFPPF10_AUTONEG),
					.peer = htonl(get_switch_ofppf10_peer(i)),
				};
				memcpy(ofp_buffer+len, &port, sizeof(port));
				len += sizeof(port);
			}
			struct ofp10_switch_features res = {
				.header = {
					.version = 1,
					.type = OFPT10_FEATURES_REPLY,
					.length = htons(len),
					.xid = req.xid,
				},
				.n_buffers = htonl(MAX_BUFFERS),
				.n_tables = MAX_TABLES,
				.capabilities = OFPC10_FLOW_STATS | OFPC10_TABLE_STATS | OFPC10_PORT_STATS | OFPC10_ARP_MATCH_IP,
			};
			char dpid[8] = {0};
			memcpy(dpid+2, Zodiac_Config.MAC_address, 6);
			memcpy(&res.datapath_id, dpid, 8);
			memcpy(ofp_buffer, &res, offsetof(struct ofp10_switch_features, ports));
			ofp_tx_write(self, ofp_buffer, len);
			ret = OFP_OK;
		}
		break;

		case OFPT10_GET_CONFIG_REQUEST:
		if(ofp_tx_room(self) < sizeof(struct ofp_switch_config)){
			// noop
		} else if(length > 8){
			return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
		} else {
			struct ofp_switch_config config = {
				.header = {
					.version = 1,
					.type = OFPT10_GET_CONFIG_REPLY,
					.length = htons(sizeof(struct ofp_switch_config)),
					.xid = req.xid,
				},
				.flags = ntohs(fx_switch.flags),
				.miss_send_len = ntohs(fx_switch.miss_send_len),
			};
			ofp_tx_write(self, &config, sizeof(config));
			ret = OFP_OK;
		}
		break;

		case OFPT10_SET_CONFIG:
		if(length != sizeof(struct ofp_switch_config)){
			return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
		} else {
			struct ofp_switch_config msg;
			ofp_rx_read(self, &msg, 12);
			fx_switch.flags = ntohs(msg.flags); // XXX: add tcp_reass() support
			fx_switch.miss_send_len = ntohs(msg.miss_send_len);
			// XXX: ofp_error may be raised while setting the other fields
			ret = OFP_OK;
		}
		break;

		case OFPT10_PACKET_OUT:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			// noop
		} else if(length < 24){
			return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
		} else {
			struct ofp_packet_out hint;
			pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp_packet_out), self->rskip);
			
			void *actions = malloc(ntohs(hint.actions_len));
			if(actions == NULL){
				return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_EPERM);
			}
			
			struct fx_packet packet = {
				.in_port = hint.in_port,
			};
			if(hint.buffer_id != htonl(-1)){
				bool found = false;
				for(int i=0; i<MAX_BUFFERS; i++){
					if((fx_packet_ins[i].send_bits & 0x80) == 0){
						continue;
					}
					if(fx_packet_ins[i].buffer_id != hint.buffer_id){
						continue;
					}
					packet.data = fx_packet_ins[i].packet.data; // ownership moves
					packet.length = fx_packet_ins[i].packet.length;
					packet.capacity = fx_packet_ins[i].packet.capacity;
					packet.malloced = fx_packet_ins[i].packet.malloced;
					memset(fx_packet_ins+i, 0, sizeof(struct fx_packet_in));
					found = true;
					break;
				}
				if(found == false){
					free(actions);
					return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BUFFER_UNKNOWN);
				}
				
				uint16_t offset = offsetof(struct ofp_packet_out, actions);
				pbuf_copy_partial(self->rbuf, actions, ntohs(hint.actions_len), self->rskip+offset);
			}else{
				uint16_t len = offsetof(struct ofp_packet_out, actions);
				len += ntohs(hint.actions_len);
				
				void *data = malloc(length-len);
				if(data == NULL){ // out-of memory
					free(actions);
					return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_EPERM);
				}
				
				uint16_t offset = offsetof(struct ofp_packet_out, actions);
				pbuf_copy_partial(self->rbuf, actions, ntohs(hint.actions_len), self->rskip+offset);
				pbuf_copy_partial(self->rbuf, data, length-len, self->rskip+len);
				packet.data = data;
				packet.length = length - len;
				packet.capacity = length - len;
				packet.malloced = true;
			}
			struct fx_packet_oob oob;
			sync_oob(&packet, &oob);
			
			uintptr_t p = (uintptr_t)actions;
			uintptr_t endp = (uintptr_t)actions + ntohs(hint.actions_len);
			while(p < endp){
				struct ofp_action_header act;
				memcpy(&act, (void*)p, sizeof(act));
				
				if(p + ntohs(act.len) > endp){
					free(actions);
					if(packet.malloced){
						free(packet.data);
					}
					return ofp_write_error(self, OFPET10_BAD_ACTION, OFPBAC10_BAD_LEN);
				}
				// xxx: check more
				p += ntohs(act.len);
			}
			p = (uintptr_t)actions;
			while(p < endp){
				struct ofp_action_header act;
				memcpy(&act, (void*)p, sizeof(act));
				
				if(execute_ofp10_action(&packet, &oob, (void*)p, -1)==false){
					break;
				}
				p += ntohs(act.len);
			}
			free(actions);
			if(packet.malloced){
				free(packet.data);
			}
			ret = OFP_OK;
		}
		break;
		
		case OFPT10_FLOW_MOD:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			// noop
		} else {
			struct ofp_flow_mod hint;
			pbuf_copy_partial(self->rbuf, &hint, sizeof(hint), self->rskip);
			uint16_t offset = offsetof(struct ofp_flow_mod, actions);
			uint16_t ops_len = ntohs(hint.header.length) - offset;
			void *ops = NULL;
			
			if(ops_len > 0){
				ops = malloc(ops_len);
				if(ops == NULL){
					return ofp_write_error(self, OFPET10_FLOW_MOD_FAILED, OFPFMFC10_EPERM);
				}
				pbuf_copy_partial(self->rbuf, ops, ops_len, self->rskip + offset);
			}
			
			ret = mod_ofp10_flow(self, ops, ops_len);
		}
		break;

		// TODO: PORT_MOD

		default:
			if(ofp_tx_room(self) < 12+64){
				//noop
			}else{
				return ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_TYPE);
			}
		break;
	}
	if(ret == OFP_OK){
		self->rskip = head + length;
	} else if (ret == OFP_NOOP){
		self->rskip = head;
	}
	return ret;
}

/*
 *	@return score, negative means unmatch
 */
int match_frame_by_tuple(const struct fx_packet *packet, const struct fx_packet_oob *oob, const struct ofp_match tuple){
	int score = 0;
	if((tuple.wildcards & htonl(OFPFW_IN_PORT)) == 0){
		if(ntohl(packet->in_port) != ntohs(tuple.in_port)){
			return -1;
		}
		score += 16;
	}
	if((tuple.wildcards & htonl(OFPFW_DL_VLAN)) == 0){
		if(tuple.dl_vlan == htons(0xffff)){
			if((oob->vlan[0] & 0x10) != 0){
				return -1;
			}
		}else{
			uint8_t vlan[2];
			memcpy(vlan, &tuple.dl_vlan, 2);
			if((oob->vlan[0] & 0x0F) != (vlan[0] & 0x0F) || oob->vlan[1] != vlan[1]){
				return -1;
			}
		}
		score += 12;
	}
	if((tuple.wildcards & htonl(OFPFW_DL_VLAN_PCP)) == 0){
		if((oob->vlan[0] & 0x10) != 0){
			if((oob->vlan[0]>>5) != tuple.dl_vlan_pcp){
				return -1;
			}
		}
		score += 3;
	}
	if((tuple.wildcards & htonl(OFPFW_DL_DST)) == 0){
		if(memcmp(packet->data, tuple.dl_dst, OFP10_ETH_ALEN) != 0){
			return -1;
		}
		score += 48;
	}
	if((tuple.wildcards & htonl(OFPFW_DL_SRC)) == 0){
		if(memcmp(packet->data+OFP10_ETH_ALEN, tuple.dl_src, OFP10_ETH_ALEN) != 0){
			return -1;
		}
		score += 48;
	}
	if((tuple.wildcards & htonl(OFPFW_DL_TYPE)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, &tuple.dl_type, 2) != 0){
			return -1;
		}
		score += 16;
	}
	if((tuple.wildcards & htonl(OFPFW_NW_PROTO)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2) != 0){
			return -1;
		}
		struct ip_hdr *iphdr = packet->data + oob->eth_type_offset + 2;
		if(IPH_PROTO(iphdr) != tuple.nw_proto){
			return -1;
		}
		score += 8;
	}
	if((tuple.wildcards & htonl(OFPFW_TP_SRC)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2) != 0){
			return -1;
		}
		struct ip_hdr *iphdr = packet->data + oob->eth_type_offset + 2;
		if(IPH_PROTO(iphdr) == IP_PROTO_TCP){
			struct tcp_hdr *tcphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
			if(memcmp(&tcphdr->src, &tuple.tp_src, 2)){
				return -1;
			}
		}else if(IPH_PROTO(iphdr) == IP_PROTO_UDP){
			struct udp_hdr *udphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
			if(memcmp(&udphdr->src, &tuple.tp_src, 2)){
				return -1;
			}
		}
		score += 32;
	}
	if((tuple.wildcards & htonl(OFPFW_TP_DST)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2) != 0){
			return -1;
		}
		struct ip_hdr *iphdr = packet->data + oob->eth_type_offset + 2;
		if(IPH_PROTO(iphdr) == IP_PROTO_TCP){
			struct tcp_hdr *tcphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
			if(memcmp(&tcphdr->dest, &tuple.tp_dst, 2)){
				return -1;
			}
		}else if(IPH_PROTO(iphdr) == IP_PROTO_UDP){
			struct udp_hdr *udphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
			if(memcmp(&udphdr->dest, &tuple.tp_dst, 2)){
				return -1;
			}
		}
		score += 32;
	}
	if((tuple.wildcards & htonl(OFPFW_NW_SRC_MASK)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2) != 0){
			return -1;
		}
		struct ip_hdr *iphdr = packet->data + oob->eth_type_offset + 2;
		int bits = (tuple.wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT;
		if((ntohl(iphdr->src.addr)>>bits) != (ntohl(tuple.nw_src)>>bits)){
			return -1;
		}
		if(bits < 32){
			score += 32-bits;
		}
	}
	if((tuple.wildcards & htonl(OFPFW_NW_DST_MASK)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2) != 0){
			return -1;
		}
		struct ip_hdr *iphdr = packet->data + oob->eth_type_offset + 2;
		int bits = (tuple.wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT;
		if((ntohl(iphdr->dest.addr)>>bits) != (ntohl(tuple.nw_dst)>>bits)){
			return -1;
		}
		if(bits < 32){
			score += 32-bits;
		}
	}
	if((tuple.wildcards & htonl(OFPFW_NW_TOS)) == 0){
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2) != 0){
			return -1;
		}
		struct ip_hdr *iphdr = packet->data + oob->eth_type_offset + 2;
		if(IPH_TOS(iphdr) != tuple.nw_tos){
			return -1;
		}
		score += 8;
	}
	return score;
}

void execute_ofp10_flow(struct fx_packet *packet, struct fx_packet_oob *oob, int flow){
	uintptr_t pos = (uintptr_t)fx_flows[flow].ops; 
	while(pos < (uintptr_t)fx_flows[flow].ops + fx_flows[flow].ops_length){
		struct ofp_action_header act;
		memcpy(&act, (void*)pos, sizeof(act));
		if(execute_ofp10_action(packet, oob, (void*)pos, flow) == false){
			break;
		}
		pos += ntohs(act.len);
	}
}
