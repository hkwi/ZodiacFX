/**
 * @file
 * openflow_13.c
 *
 * This file contains the OpenFlow v1.3 (0x04) specific functions
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
 *         Hiroaki KAWAI <hiroaki.kawai@gmail.com>
 *
 */

#include <asf.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>
#include <lwip/udp.h>
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "timers.h"

// limitation from ofp13_flow_removed
#define MAX_MATCH_LEN (OFP_BUFFER_LEN - 54)

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int OF_Version;
extern int iLastFlow;

/*
*	Converts a 64bit value from host to network format
*
*	@param n - value to convert.
*
*/
static inline uint64_t (htonll)(uint64_t n)
{
	return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

extern bool disable_ofp_pipeline;
extern char ofp_buffer[OFP_BUFFER_LEN];
extern struct controller controllers[MAX_CONTROLLERS];
extern struct fx_table_count fx_table_counts[MAX_TABLES];
extern struct fx_flow fx_flows[MAX_FLOWS];
extern struct fx_flow_timeout fx_flow_timeouts[MAX_FLOWS];
extern struct fx_flow_count fx_flow_counts[MAX_FLOWS];
extern uint32_t fx_buffer_id;
extern struct fx_packet_in fx_packet_ins[MAX_BUFFERS];
extern struct fx_switch_config fx_switch;
extern struct fx_port fx_ports[MAX_PORTS];
extern struct fx_port_count fx_port_counts[MAX_PORTS];
extern struct fx_meter_band fx_meter_bands[MAX_METER_BANDS];

// fields are in host byte order
struct ofp13_filter {
	bool strict;
	uint8_t table_id;
	uint16_t priority;
	uint32_t out_port;
	uint32_t out_group;
	uint64_t cookie; // in network byte order
	uint64_t cookie_mask; // in network byte order
	uint16_t oxm_length;
	void *oxm;
};

/*
 * scans flow table for matching flow
 */
static int filter_ofp13_flow(int first, struct ofp13_filter filter){
	for(int i=first; i<iLastFlow; i++){
		if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0){
			continue;
		}
		if (filter.table_id != OFPTT13_ALL && filter.table_id != fx_flows[i].table_id){
			continue;
		}
		if (filter.cookie_mask != 0 && filter.cookie != (fx_flows[i].cookie & filter.cookie_mask)){
			continue;
		}
		if(filter.strict){
			if (filter.priority != fx_flows[i].priority){
				continue;
			}
			if(false == oxm_strict_equals(fx_flows[i].oxm, fx_flows[i].oxm_length, filter.oxm, filter.oxm_length)){
				continue;
			}
		} else {
			if(field_match13(fx_flows[i].oxm, fx_flows[i].oxm_length, filter.oxm, filter.oxm_length) == 0){
				continue;
			}
		}
		if (filter.out_port != OFPP13_ANY){
			bool out_port_match = false;
			uintptr_t ops = (uintptr_t)fx_flows[i].ops;
			while(ops < (uintptr_t)fx_flows[i].ops + fx_flows[i].ops_length){
				struct ofp13_instruction inst;
				memcpy(&inst, (void*)ops, sizeof(inst));
				
				if(inst.type==htons(OFPIT13_APPLY_ACTIONS) || inst.type==htons(OFPIT13_WRITE_ACTIONS)){
					uintptr_t act = ops + offsetof(struct ofp13_instruction_actions, actions);
					while(act < ops + ntohs(inst.len)){
						struct ofp13_action_header action;
						memcpy(&action, (void*)act, sizeof(action));
						
						if(action.type==htons(OFPAT13_OUTPUT)){
							struct ofp13_action_output output;
							memcpy(&output, (void*)act, sizeof(output));
							if (output.port == filter.out_port){
								out_port_match = true;
							}
						}
						act += ntohs(action.len);
					}
				}
				ops += ntohs(inst.len);
			}
			if(out_port_match==false){
				continue;
			}
		}
		if (filter.out_group != OFPG13_ANY){
			bool out_group_match = false;
			uintptr_t ops = (uintptr_t)fx_flows[i].ops;
			while(ops < (uintptr_t)fx_flows[i].ops + fx_flows[i].ops_length){
				struct ofp13_instruction inst;
				memcpy(&inst, (void*)ops, sizeof(inst));
				
				if(inst.type==htons(OFPIT13_APPLY_ACTIONS) || inst.type==htons(OFPIT13_WRITE_ACTIONS)){
					uintptr_t act = ops + offsetof(struct ofp13_instruction_actions, actions);
					while(act < ops+ntohs(inst.len)){
						struct ofp13_action_header action;
						memcpy(&action, (void*)act, sizeof(action));
						
						if(action.type==htons(OFPAT13_GROUP)){
							struct ofp13_action_group group;
							memcpy(&group, (void*)act, sizeof(group));
							if (group.group_id == filter.out_group){
								out_group_match = true;
							}
						}
						act += ntohs(action.len);
					}
				}
				ops += ntohs(inst.len);
			}
			if(out_group_match==false){
				continue;
			}
		}
		return i;
	}
	return -1;
}

static uint16_t fill_ofp13_flow_stats(const void *cunit, int *mp_index, void *buffer, uint16_t capacity){
	struct ofp13_flow_stats_request unit;
	memcpy(&unit, cunit, sizeof(unit));
	
	struct ofp13_filter filter = {
		.cookie = unit.cookie,
		.cookie_mask = unit.cookie_mask,
		.out_group = ntohl(unit.out_group),
		.out_port = ntohl(unit.out_port),
		.table_id = unit.table_id,
		.oxm_length = ntohs(unit.match.length)-4,
		.oxm = (void*)((uintptr_t)cunit + offsetof(struct ofp13_flow_stats_request, match) + 4),
	};
	uint16_t length = 0;
	bool complete = true;
	for(int i=filter_ofp13_flow(*mp_index, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		uint16_t offset_inst = offsetof(struct ofp13_flow_stats, match) + ALIGN8(4+fx_flows[i].oxm_length);		;
		// ofp_flow_stats fixed fields are the same length with ofp_flow_mod
		*mp_index = i; // we want to revisit k.
		if(length + offset_inst + fx_flows[i].ops_length > capacity){
			complete = false;
			break;
		}
		uint32_t duration = sys_get_ms() - fx_flow_timeouts[i].init;
		struct ofp13_flow_stats stats = {
			.length = htons(offset_inst+fx_flows[i].ops_length),
			.table_id = fx_flows[i].table_id,
			.duration_sec = htonl(duration/1000U),
			.duration_nsec = htonl((duration%1000U)*1000000U),
			.priority = htons(fx_flows[i].priority),
			.idle_timeout = htons(fx_flow_timeouts[i].idle_timeout),
			.hard_timeout = htons(fx_flow_timeouts[i].hard_timeout),
			.flags = htons(fx_flows[i].flags),
			.cookie = fx_flows[i].cookie,
			.packet_count = htonll(fx_flow_counts[i].packet_count),
			.byte_count = htonll(fx_flow_counts[i].byte_count),
			.match = {
				.type = htons(OFPMT13_OXM),
				.length = htons(4+fx_flows[i].oxm_length),
			}
		};
		int len;
		uintptr_t buf = (uintptr_t)buffer + length;
		// struct ofp13_flow_stats(including ofp13_match)
		memcpy((void*)buf, &stats, sizeof(struct ofp13_flow_stats));
		// oxm_fields
		len = offsetof(struct ofp13_flow_stats, match) + 4;
		buf = (uintptr_t)buffer + length + len;
		memset((void*)buf, 0, ALIGN8(fx_flows[i].oxm_length+4)-4);
		memcpy((void*)buf, fx_flows[i].oxm, fx_flows[i].oxm_length);
		// instructions
		len = offset_inst;
		buf = (uintptr_t)buffer + length + len;
		memcpy((void*)buf, fx_flows[i].ops, fx_flows[i].ops_length);
		length += offset_inst + fx_flows[i].ops_length;
	}
	if(complete){
		*mp_index = -1; // complete
	}
	return length;
}

static uint16_t fill_ofp13_aggregate_stats(const void *cunit, int *mp_index, void *buffer, uint16_t capacity){
	if(capacity < 24){
		return 0;
	}
	struct ofp13_aggregate_stats_request unit;
	memcpy(&unit, cunit, sizeof(unit));
	
	struct ofp13_filter filter = {
		.cookie = unit.cookie,
		.cookie_mask = unit.cookie_mask,
		.out_group = ntohl(unit.out_group),
		.out_port = ntohl(unit.out_port),
		.table_id = unit.table_id,
		.oxm_length = ntohs(unit.match.length)-4,
		.oxm = (void*)((uintptr_t)cunit + offsetof(struct ofp13_aggregate_stats_request, match) + 4),
	};
	struct ofp13_aggregate_stats_reply res = {0};
	for(int i=filter_ofp13_flow(*mp_index, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		res.packet_count += fx_flow_counts[i].packet_count;
		res.byte_count += fx_flow_counts[i].byte_count;
		res.flow_count++;
	}
	memcpy(buffer, &res, 24);
	*mp_index = -1;
	return 24;
}

static uint16_t fill_ofp13_table_stats(int *mp_index, void *buffer, uint16_t capacity){
	if(capacity < 24){
		return 0;
	}
	bool complete = true;
	uint16_t length = 0;
	for(int i=*mp_index; i<MAX_TABLES; i++){
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
		struct ofp13_table_stats stat = {
			.table_id = i,
			.active_count = htonl(active),
			.matched_count = htonll(fx_table_counts[i].matched),
			.lookup_count = htonll(fx_table_counts[i].lookup),
		};
		uintptr_t buf = (uintptr_t)buffer+length;
		memcpy((void*)buf, &stat, 24);
		length += 24;
	}
	if(complete){
		*mp_index = -1;
	}
	return length;
}

static void make_port_stats(uint32_t port, struct ofp13_port_stats *stats){
	sync_switch_port_counts(port);
	uint64_t duration = sys_get_ms64() - fx_ports[port].init;
	stats->port_no = htonl(port+1);
	stats->rx_packets = htonll(fx_port_counts[port].rx_packets);
	stats->tx_packets = htonll(fx_port_counts[port].tx_packets);
	stats->rx_bytes = htonll(fx_port_counts[port].rx_bytes);
	stats->tx_bytes = htonll(fx_port_counts[port].tx_bytes);
	stats->rx_dropped = htonll(fx_port_counts[port].rx_dropped);
	stats->tx_dropped = htonll(fx_port_counts[port].tx_dropped);
	stats->rx_errors = htonll(fx_port_counts[port].rx_errors);
	stats->tx_errors = htonll(fx_port_counts[port].tx_errors);
	stats->rx_frame_err = htonll(fx_port_counts[port].rx_frame_err);
	stats->rx_over_err = htonll(fx_port_counts[port].rx_over_err);
	stats->rx_crc_err = htonll(fx_port_counts[port].rx_crc_err);
	stats->collisions = htonll(fx_port_counts[port].collisions);
	stats->duration_sec = htonl(duration/1000u);
	stats->duration_nsec = htonl((duration%1000u)*1000000u);
}

static uint16_t fill_ofp13_port_stats(uint32_t port, int *mp_index, void *buffer, uint16_t capacity){
	uint32_t port_index = ntohl(port)-1;
	struct ofp13_port_stats stat;
	if(port_index < OFPP13_MAX){
		make_port_stats(port_index, &stat);
		memcpy(buffer, &stat, 112);
		*mp_index = -1;
		return 112;
	} else if(port == htonl(OFPP13_ANY)){
		bool complete = true;
		uint16_t len = 0;
		for(int i=*mp_index; i<4; i++){
			if(Zodiac_Config.of_port[i] == 1){
				*mp_index=i;
				if(len + 112 > capacity){
					complete = false;
					break;
				}
				make_port_stats(i, &stat);
				memcpy((void*)((uintptr_t)buffer + len), &stat, 112);
				len += 112;
			}
		}
		if(complete){
			*mp_index = -1;
		}
		return len;
	}
	return 0;
}

static uint16_t fill_ofp13_port_desc(int *mp_index, void *buffer, uint16_t capacity){
	bool complete = true;
	uint16_t length = 0;
	for(int i=*mp_index; i<4; i++){
		*mp_index = i;
		if(Zodiac_Config.of_port[i] == 1){
			if(length + 64 > capacity){
				complete = false;
				break;
			}
			uint32_t curr = get_switch_ofppf13_curr(i);
			struct ofp13_port port = {
				.port_no = htonl(i+1),
				.config = htonl(get_switch_config(i)),
				.state = htonl(get_switch_status(i)),
				.curr = htonl(curr),
				.advertised = htonl(get_switch_ofppf13_advertised(i)),
				.supported = htonl(	OFPPF13_COPPER | OFPPF13_PAUSE | OFPPF13_PAUSE_ASYM |OFPPF13_100MB_FD \
					| OFPPF13_100MB_HD | OFPPF13_10MB_FD | OFPPF13_10MB_HD | OFPPF13_AUTONEG),
				.peer = htonl(get_switch_ofppf13_peer(i)),
				.max_speed = htonl(100000u),
			};
			memcpy(port.hw_addr, Zodiac_Config.MAC_address, 6);
			snprintf(port.name, OFP13_MAX_PORT_NAME_LEN, "eth%d", i);
			if((curr & (OFPPF13_100MB_FD|OFPPF13_100MB_HD)) != 0){
				port.curr_speed = htonl(100000u);
			} else if((curr & (OFPPF13_10MB_FD|OFPPF13_10MB_HD)) != 0){
				port.curr_speed = htonl(10000u);
			}
			memcpy((void*)((uintptr_t)buffer + length), &port, 64);
			length += 64;
		}
	}
	if(complete){
		*mp_index = -1;
	}
	return length;
}

static enum ofp_pcb_status ofp13_write_mp_error(struct ofp_pcb *self, uint16_t ofpet, uint16_t ofpec){
	struct ofp13_multipart_request mpreq;
	memcpy(&mpreq, self->mpreq_hdr, 16);
	uint16_t length = ntohs(mpreq.header.length);
	
	if(self->mpreq_pos + ofp_rx_length(self) < length || ofp_tx_room(self) < 28){
		return OFP_NOOP;
	}
	uint16_t remaining = length - self->mpreq_pos;
	self->rskip += remaining;
	self->mpreq_pos += remaining;
	
	struct ofp_error_msg err = {
		.header = {
			.version = 4,
			.type = OFPT13_ERROR,
			.length = htons(28),
			.xid = mpreq.header.xid,
		},
		.type = htons(ofpet),
		.code = htons(ofpec),
	};
	memcpy(ofp_buffer, &err, 12);
	memcpy(ofp_buffer+12, self->mpreq_hdr, 16);
	ofp_tx_write(self, ofp_buffer, 12+16);

	self->mpreq_pos = 0;
	self->mpreq_on = false;
	return OFP_OK;
}

enum ofp_pcb_status ofp13_multipart_complete(struct ofp_pcb *self){
	struct ofp13_multipart_request mpreq;
	struct ofp13_multipart_reply mpres;
	memcpy(&mpreq, self->mpreq_hdr, 16);
	memcpy(&mpres, self->mpreq_hdr, 16);
	mpres.header.type = OFPT13_MULTIPART_REPLY;
	uint16_t length = ntohs(mpreq.header.length);
	char unit[MP_UNIT_MAXSIZE];
	
	while(self->mpreq_pos != 0){
		switch(ntohs(mpreq.type)){
			case OFPMP13_DESC:
			if(ofp_tx_room(self) < 16+1056){
				return OFP_NOOP;
			}else if(length > 16){ // has no body in request
				return ofp13_write_mp_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
			}else{
				mpres.header.length = htons(16+1056);
				mpres.flags = 0;
				struct ofp13_desc zodiac_desc = {
					.mfr_desc = "Northbound Networks",
					.hw_desc  = "Zodiac-FX Rev.A",
					.sw_desc  = VERSION,
					.serial_num= "",
					.dp_desc  = "World's smallest OpenFlow switch!"
				};
				memcpy(ofp_buffer, &mpres, 16);
				memcpy(ofp_buffer+16, &zodiac_desc, 1056);
				ofp_tx_write(self, ofp_buffer, 16+1056);
			}
			break;
			
			case OFPMP13_FLOW:
			{
				struct ofp13_flow_stats_request hint;
				if(self->mp_out_index < 0){
					if(ofp_rx_length(self) < 40){
						return OFP_NOOP;
					}
					pbuf_copy_partial(self->rbuf, &hint, 40, self->rskip);
					uint16_t unitreqlen = offsetof(struct ofp13_flow_stats_request, match) + ALIGN8(ntohs(hint.match.length));
					if(ofp_rx_length(self) < unitreqlen){
						return OFP_NOOP;
					}
					self->mpreq_pos += ofp_rx_read(self, self->mp_in, unitreqlen);
					self->mp_out_index = 0;
				} else {
					// restore hint
					memcpy(&hint, self->mp_in, 40);
				}
				memcpy(unit, self->mp_in, offsetof(struct ofp13_flow_stats_request, match) + ALIGN8(ntohs(hint.match.length)));
				uint16_t unitlength = fill_ofp13_flow_stats(unit,
					&self->mp_out_index, ofp_buffer+16, ofp_tx_room(self)-16);
				mpres.flags = htons(OFPMPF13_REPLY_MORE);
				if(self->mp_out_index < 0){
					mpres.flags = 0;
				}
				mpres.header.length = htons(16+unitlength);
				memcpy(ofp_buffer, &mpres, 16);
				ofp_tx_write(self, ofp_buffer, 16+unitlength);
			}
			break;
			
			case OFPMP13_AGGREGATE:
			if(ofp_rx_length(self) < 40){
				return OFP_NOOP;
			}else{
				struct ofp13_aggregate_stats_request hint;
				if(self->mp_out_index < 0){
					pbuf_copy_partial(self->rbuf, &hint, 40, self->rskip);
					uint16_t unitreqlen = offsetof(struct ofp13_aggregate_stats_request, match) + ALIGN8(ntohs(hint.match.length));
					if(ofp_rx_length(self) < unitreqlen){
						return OFP_NOOP;
					}
					self->mpreq_pos += ofp_rx_read(self, self->mp_in, unitreqlen);
					self->mp_out_index = 0;
				} else {
					// restore
					memcpy(&hint, self->mp_in, 40);
				}
				memcpy(unit, self->mp_in, offsetof(struct ofp13_aggregate_stats_request, match) + ALIGN8(ntohs(hint.match.length)));
				uint16_t unitlength = fill_ofp13_aggregate_stats(unit,
					&self->mp_out_index, ofp_buffer+16, ofp_tx_room(self)-16);
				if(unitlength == 0){
					return OFP_NOOP;
				}
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPMPF13_REPLY_MORE);
				}
				mpres.header.length = htons(16+unitlength);
				memcpy(ofp_buffer, &mpres, 16);
				ofp_tx_write(self, ofp_buffer, 16+unitlength);
			}
			break;
			
			case OFPMP13_TABLE:
			if(ofp_tx_room(self) < 16+24){
				return OFP_NOOP;
			} else {
				if(self->mp_out_index < 0){
					self->mp_out_index = 0;
				}
				uint16_t unitlength = fill_ofp13_table_stats(
					&self->mp_out_index, ofp_buffer+16, ofp_tx_room(self)-16);
				if(unitlength==0){
					return OFP_NOOP;
				}
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPMPF13_REPLY_MORE);
				}
				mpres.header.length = htons(16+unitlength);
				memcpy(ofp_buffer, &mpres, 16);
				ofp_tx_write(self, ofp_buffer, 16+unitlength);
			}
			break;
			
			case OFPMP13_PORT_STATS:
			if(ofp_rx_length(self) < 8 || ofp_tx_room(self) < 16+112){
				return OFP_NOOP;
			}else{
				if(self->mp_out_index < 0){
					self->mp_out_index = 0;
				}
				if(length != 16+8){
					return ofp13_write_mp_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
				}
				struct ofp13_port_stats_request hint;
				self->mpreq_pos += ofp_rx_read(self, &hint, 8);
				
				uint32_t port_no = ntohl(hint.port_no);
				if(port_no <= OFPP13_MAX || port_no == OFPP13_ANY){
					uint16_t unitlength = fill_ofp13_port_stats(hint.port_no,
						&self->mp_out_index, ofp_buffer+16, ofp_tx_room(self)-16);
					mpres.flags = 0;
					if(self->mp_out_index >= 0){
						mpres.flags = htons(OFPMPF13_REPLY_MORE);
					}
					mpres.header.length = htons(16+unitlength);
					memcpy(ofp_buffer, &mpres, 16);
					ofp_tx_write(self, ofp_buffer, 16+unitlength);
				} else {
					return ofp13_write_mp_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_PORT);
				}
			}
			break;
			
			case OFPMP13_PORT_DESC:
			if(ofp_tx_room(self) < 64){
				return OFP_NOOP;
			} else if (length > 16){
				return ofp13_write_mp_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
			} else {
				if(self->mp_out_index < 0){
					self->mp_out_index = 0;
				}
				uint16_t capacity = ofp_tx_room(self);
				if(capacity > OFP_BUFFER_LEN){
					capacity = OFP_BUFFER_LEN;
				}
				
				uint16_t unitlength = fill_ofp13_port_desc(
					&self->mp_out_index, ofp_buffer+16, capacity-16);
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPMPF13_REPLY_MORE);
				}
				mpres.header.length = htons(16+unitlength);
				memcpy(ofp_buffer, &mpres, 16);
				ofp_tx_write(self, ofp_buffer, 16+unitlength);
			}
			break;
			
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
					.type = htons(OFPET13_BAD_REQUEST),
					.code = htons(OFPBRC13_BAD_MULTIPART),
				};
				memcpy(reply, &err, 12);
				memcpy(reply+12, ofp_buffer, tail);
				ofp_tx_write(self, reply, 12+tail);
			}
			break;
		}
		if (self->mpreq_pos >= length && (ntohs(mpres.flags) & OFPMPF13_REQ_MORE) == 0){
			self->mpreq_pos = 0;
			self->mpreq_on = false;
		}
	}
	return OFP_OK;
}

static enum ofp_pcb_status add_ofp13_flow(struct ofp_pcb *self, void *oxm, uint16_t oxm_len, void *ops, uint16_t ops_len){
	struct ofp13_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp13_flow_mod), self->rskip);
	uint16_t length = ntohs(hint.header.length);
	
	if(hint.table_id > OFPTT13_MAX){
		if(oxm != NULL) free(oxm);
		if(ops != NULL) free(ops);
		return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
	}
	if((hint.flags & htons(OFPFF13_CHECK_OVERLAP)) != 0){
		int overlap = -1;
		for(int i=0; i<iLastFlow; i++){
			if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0
					|| hint.table_id != fx_flows[i].table_id
					|| ntohs(hint.priority) != fx_flows[i].priority){
				continue;
			}
			if(field_match13(oxm, oxm_len, fx_flows[i].oxm, fx_flows[i].oxm_length) != 1){
				overlap = i;
				break;
			}
			if(field_match13(fx_flows[i].oxm, fx_flows[i].oxm_length, oxm, oxm_len) != 1){
				overlap = i;
				break;
			}
		}
		if(overlap >= 0){
			if(oxm != NULL) free(oxm);
			if(ops != NULL) free(ops);
			return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
		}
	}

	struct ofp13_filter filter = {
		.strict = true,
		.table_id = hint.table_id,
		.priority = ntohs(hint.priority),
		.out_port = OFPP13_ANY,
		.out_group = OFPG13_ANY,
		.cookie = hint.cookie,
		.cookie_mask = hint.cookie_mask,
		.oxm_length = oxm_len,
		.oxm = oxm,
	};
	int found = filter_ofp13_flow(0, filter);
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
			if(oxm != NULL) free(oxm);
			if(ops != NULL) free(ops);
			return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		}else{
			n = iLastFlow++;
		}
	}
	
	fx_flows[n].send_bits = FX_FLOW_ACTIVE;
	fx_flows[n].table_id = hint.table_id;
	fx_flows[n].priority = ntohs(hint.priority);
	fx_flows[n].flags = ntohs(hint.flags);
	if(fx_flows[n].oxm != NULL){
		free(fx_flows[n].oxm);
	}
	fx_flows[n].oxm = oxm;
	fx_flows[n].oxm_length = oxm_len;
	if(fx_flows[n].ops != NULL){
		free(fx_flows[n].ops);
	}
	fx_flows[n].ops = ops;
	fx_flows[n].ops_length = ops_len;
	fx_flows[n].cookie = hint.cookie;
	
	fx_flow_timeouts[n].hard_timeout = ntohs(hint.hard_timeout);
	fx_flow_timeouts[n].idle_timeout = ntohs(hint.idle_timeout);
	fx_flow_timeouts[n].init = sys_get_ms64();
	fx_flow_timeouts[n].update = sys_get_ms();
	
	if(found < 0 || (hint.flags & htons(OFPFF13_RESET_COUNTS)) != 0){
		fx_flow_counts[n].byte_count = 0;
		fx_flow_counts[n].packet_count = 0;
	}
	if(ntohl(hint.buffer_id) != OFP13_NO_BUFFER){
		// TODO: enqueue buffer
	}
	self->rskip += length;
	return OFP_OK;
}

static enum ofp_pcb_status modify_ofp13_flow(struct ofp_pcb *self, void *oxm, uint16_t oxm_len, void *ops, uint16_t ops_len, bool strict){
	struct ofp13_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp13_flow_mod), self->rskip);
	uint16_t length = ntohs(hint.header.length);
	
	if(hint.table_id > OFPTT13_MAX){
		return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
	}
	
	struct ofp13_filter filter = {
		.strict = strict,
		.table_id = hint.table_id,
		.priority = ntohs(hint.priority),
		.out_port = OFPP13_ANY,
		.out_group = OFPG13_ANY,
		.cookie = hint.cookie,
		.cookie_mask = hint.cookie_mask,
		.oxm_length = oxm_len,
		.oxm = oxm,
	};

	// We'll copy ops per flow entry.
	int count = 0;
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		count++;
	}
	void **tmp = malloc(count*sizeof(char*));
	for(int i=0; i<count; i++){
		tmp[i] = malloc(ops_len);
		if(tmp[i]==NULL){
			for(int j=0; j<i; j++){
				free(tmp[j]);
			}
			if(oxm != NULL) free(oxm);
			if(ops != NULL) free(ops);
			return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
		}
	}
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		if(fx_flows[i].ops != NULL){
			free(fx_flows[i].ops);
		}
		void *flow_ops = tmp[--count];
		memcpy(flow_ops, ops, ops_len);
		fx_flows[i].ops = flow_ops;
		fx_flows[i].ops_length = ops_len;
		
		if((hint.flags & htons(OFPFF13_RESET_COUNTS)) != 0){
			fx_flow_counts[i].byte_count = 0;
			fx_flow_counts[i].packet_count = 0;
		}
	}
	if(oxm != NULL) free(oxm);
	if(ops != NULL) free(ops);
	free(tmp);
	if(hint.buffer_id != htonl(OFP13_NO_BUFFER)){
		// TODO: enqueue buffer
	}
	self->rskip += length;
	return OFP_OK;
}

static enum ofp_pcb_status delete_ofp13_flow(struct ofp_pcb *self, void *oxm, uint16_t oxm_len, void *ops, uint16_t ops_len, bool strict){
	struct ofp13_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp13_flow_mod), self->rskip);
	uint16_t length = ntohs(hint.header.length);
	
	struct ofp13_filter filter = {
		.strict = strict,
		.table_id = hint.table_id,
		.priority = ntohs(hint.priority),
		.out_port = ntohl(hint.out_port),
		.out_group = ntohl(hint.out_group),
		.cookie = hint.cookie,
		.cookie_mask = hint.cookie_mask,
		.oxm_length = oxm_len,
		.oxm = oxm,
	};
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		if((fx_flows[i].flags & OFPFF13_SEND_FLOW_REM) != 0){
			uint8_t send_bits = 0;
			for(int j=0; j<MAX_CONTROLLERS; j++){
				send_bits |= 1<<j;
			}
			fx_flows[i].send_bits = send_bits;
			fx_flows[i].reason = OFPRR13_DELETE;
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
	if(oxm != NULL) free(oxm);
	if(ops != NULL) free(ops);
	self->rskip += length;
	return 0;
}

/*
 * context : ofp_buffer is filled by request heading 64 bytes or less
 */
static enum ofp_pcb_status mod_ofp13_flow(struct ofp_pcb *self, void *oxm, uint16_t oxm_len, void *ops, uint16_t ops_len){
	struct ofp13_flow_mod hint;
	pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp13_flow_mod), self->rskip);
	switch(hint.command){
		case OFPFC13_ADD:
			return add_ofp13_flow(self, oxm, oxm_len, ops, ops_len);
		
		case OFPFC13_MODIFY:
			return modify_ofp13_flow(self, oxm, oxm_len, ops, ops_len, false);
		
		case OFPFC13_MODIFY_STRICT:
			return modify_ofp13_flow(self, oxm, oxm_len, ops, ops_len, true);
		
		case OFPFC13_DELETE:
			return delete_ofp13_flow(self, oxm, oxm_len, ops, ops_len, false);
		
		case OFPFC13_DELETE_STRICT:
			return delete_ofp13_flow(self, oxm, oxm_len, ops, ops_len, true);
		
		default:
			return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_COMMAND);
	}
}

static enum ofp_pcb_status add_ofp13_meter(struct ofp_pcb *self){
	struct ofp13_meter_mod req;
	pbuf_copy_partial(self->rbuf, &req, sizeof(struct ofp13_meter_mod), self->rskip);
	uint16_t length = ntohs(req.header.length);
	
	if(ntohl(req.meter_id)==OFPM13_ALL){
		return ofp_write_error(self, OFPET13_METER_MOD_FAILED, OFPMMFC13_INVALID_METER);
	}
	return ofp_write_error(self, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_METERS);
	// XXX: todo
}

static enum ofp_pcb_status modify_ofp13_meter(struct ofp_pcb *self){
	struct ofp13_meter_mod req;
	pbuf_copy_partial(self->rbuf, &req, sizeof(struct ofp13_meter_mod), self->rskip);
	uint16_t length = ntohs(req.header.length);
	
	int count = 0;
	uintptr_t pos = (uintptr_t)req.bands;
	while(pos < (uintptr_t)req.bands + length){
		struct ofp13_meter_band_header *band = (void*)pos;
		count++;
		pos += ntohs(band->len);
	}
	if(req.meter_id != htonl(OFPM13_ALL)){
		count -= MAX_METER_BANDS;
	}else{
		for(int i=0; i<MAX_METER_BANDS; i++){
			if(fx_meter_bands[i].meter_id == 0 || fx_meter_bands[i].meter_id == req.meter_id){
				count--;
			}
		}
	}
	if(count > 0){
		return ofp_write_error(self, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
	}
	// XXX: implement
	self->rskip += length;
	return 0;
}

static enum ofp_pcb_status delete_ofp13_meter(struct ofp_pcb *self){
	struct ofp13_meter_mod req;
	pbuf_copy_partial(self->rbuf, &req, sizeof(struct ofp13_meter_mod), self->rskip);
	uint16_t length = ntohs(req.header.length);
	
	uint32_t meter_id = ntohl(req.meter_id);
	if(meter_id == OFPM13_ALL){
		for(int i=0; i<MAX_METER_BANDS; i++){
			fx_meter_bands[i].meter_id = 0;
		}
	} else if(meter_id <= OFPM13_MAX){
		for(int i=0; i<MAX_METER_BANDS; i++){
			if(fx_meter_bands[i].meter_id == req.meter_id){
				fx_meter_bands[i].meter_id = 0;
			}
		}
	}
	// XXX: implement controller, slowpath
	self->rskip += length;
	return 0;
}

static enum ofp_pcb_status mod_ofp13_meter(struct ofp_pcb *self){
	if(ofp_rx_length(self) < sizeof(struct ofp13_meter_mod)){
		return OFP_NOOP;
	};
	struct ofp13_meter_mod req;
	pbuf_copy_partial(self->rbuf, &req, sizeof(struct ofp13_meter_mod), self->rskip);
	uint16_t length = ntohs(req.header.length);
	if(length != sizeof(struct ofp13_meter_mod)){
		return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC10_BAD_LEN);
	}
	self->rskip += length;
	
	uint32_t meter_id = ntohl(req.meter_id);
	// meter_id starts from 1
	if(meter_id==0 || (meter_id>OFPM13_MAX
			&& meter_id!=OFPM13_SLOWPATH && meter_id!=OFPM13_CONTROLLER
			&& meter_id!=OFPM13_ALL)){
		return ofp_write_error(self, OFPET13_METER_MOD_FAILED, OFPMMFC13_INVALID_METER);
	}
	switch(ntohs(req.command)){
		case OFPMC13_ADD:
			return add_ofp13_meter(self);
		case OFPMC13_MODIFY:
			return modify_ofp13_meter(self);
		case OFPMC13_DELETE:
			return delete_ofp13_meter(self);
		default:
			return ofp_write_error(self, OFPET13_METER_MOD_FAILED, OFPFMFC13_BAD_COMMAND);
	}
}

static uint16_t mod_ofp13_group(const void *cmsg){
	struct ofp13_group_mod req;
	memcpy(&req, cmsg, sizeof(struct ofp13_group_mod));
	
	uint32_t group_id = ntohl(req.group_id);
	if(group_id > OFPG13_MAX){
		
	}
	// TODO: implement this
	return 0;
}

static int bits_on(const uint8_t *data, int len){
	int r = 0;
	for(int i=0; i<len; i++){
		if(data[i]&0x80) r++;
		if(data[i]&0x40) r++;
		if(data[i]&0x20) r++;
		if(data[i]&0x10) r++;
		if(data[i]&0x08) r++;
		if(data[i]&0x04) r++;
		if(data[i]&0x02) r++;
		if(data[i]&0x01) r++;
	}
	return r;
}

/*
 *	@return score negative means unmatch
 */
int match_frame_by_oxm(const struct fx_packet *packet, const struct fx_packet_oob *oob, const void *oxm, uint16_t oxm_length){
	const uint8_t *data = packet->data;
	int count = 0;
	for(const uint8_t *pos=oxm; pos<(const uint8_t*)oxm+oxm_length; pos+=4+pos[3]){
		if(pos[0]==0x80 && pos[1]==0x00){
			int has_mask = pos[2] & 0x01;
			switch(pos[2]>>1){
				case OFPXMT13_OFB_IN_PORT:
				if(memcmp(&packet->in_port, pos+4, 4) != 0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_IN_PHY_PORT:
				if(memcmp(packet->in_phy_port, pos+4, 4) != 0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_METADATA:
				{
					union {
						uint64_t raw;
						char b[8];
					} value = { .raw = packet->metadata };
					if(has_mask){
						for(int i=0; i<8; i++){
							if(value.b[i] & pos[12+i] != pos[4+i]){
								return -1;
							}
						}
						count += bits_on(pos+12, 8);
					} else {
						if(memcmp(value.b, pos+4, 8) != 0){
							return -1;
						}
						count += 64;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_DST:
				if(has_mask){
					for(int i=0; i<6; i++){
						if((data[i] & pos[10+i]) != pos[4+i]){
							return -1;
						}
					}
					count += bits_on(pos+10, 6);
				}else{
					for(int i=0; i<6; i++){
						if(data[i] != pos[4+i]){
							return -1;
						}
					}
					count += 48;
				}
				break;
				
				case OFPXMT13_OFB_ETH_SRC:
				if(has_mask){
					for(int i=0; i<6; i++){
						if((data[6+i] & pos[10+i]) != pos[4+i]){
							return -1;
						}
					}
					count += bits_on(pos+10, 6);
					}else{
					for(int i=0; i<6; i++){
						if(data[6+i] != pos[4+i]){
							return -1;
						}
					}
					count += 48;
				}
				break;
				
				case OFPXMT13_OFB_ETH_TYPE:
				if(memcmp(packet->data + oob->eth_type_offset, pos+4, 2)!=0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_VLAN_VID:
				if(has_mask){
					if((oob->vlan[0] & pos[6]) != pos[4]){
						return -1;
					}
					if((oob->vlan[1] & pos[7]) != pos[5]){
						return -1;
					}
					count += bits_on(pos+6, 2);
				} else {
					if((oob->vlan[0] & 0x1F) != pos[4]){
						return -1;
					}
					if(oob->vlan[1] != pos[5]){
						return -1;
					}
					count += 16;
				}
				break;
				
				case OFPXMT13_OFB_VLAN_PCP:
				if(has_mask){
					if(((oob->vlan[0]>>5) & pos[5]) != pos[4]){
						return -1;
					}
					count += bits_on(pos+5, 1);
				}else{
					if(oob->vlan[0]>>5 != pos[4]){
						return -1;
					}
					count += 3;
				}
				break;
				
				case OFPXMT13_OFB_IP_DSCP:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
					struct ip_hdr *hdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_TOS(hdr)>>2 != pos[4]){
						return -1;
					}
				} else if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV6, 2)==0){
					return -1; // TODO
				} else {
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_IP_ECN:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
					struct ip_hdr *hdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if((IPH_TOS(hdr)&0x03) != pos[4]){
						return -1;
					}
				} else if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV6, 2)==0){
					return -1; // TODO
				} else {
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_IPV4_SRC:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)!=0){
					return -1;
				}else{
					struct ip_hdr *hdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(has_mask){
						union {
							uint32_t raw;
							uint8_t b[4];
						} value = { .raw=hdr->src.addr };
						for(int i=0; i<4; i++){
							if(value.b[i] & pos[8+i] != pos[4+i]){
								return -1;
							}
						}
						count += bits_on(pos+8, 4);
					} else {
						if(memcmp(&hdr->src.addr, pos+4, 4) != 0){
							return -1;
						}
						count += 32;
					}
				}
				break;
				
				case OFPXMT13_OFB_IPV4_DST:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)!=0){
					return -1;
				}else{
					struct ip_hdr *hdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(has_mask){
						union {
							uint32_t raw;
							uint8_t b[4];
						} value = { .raw=hdr->dest.addr };
						for(int i=0; i<4; i++){
							if(value.b[i] & pos[8+i] != pos[4+i]){
								return -1;
							}
						}
						count += bits_on(pos+8, 4);
					} else {
						if(memcmp(&hdr->dest.addr, pos+4, 4) != 0){
							return -1;
						}
						count += 32;
					}
				}
				break;

				case OFPXMT13_OFB_TCP_SRC:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
					struct ip_hdr *iphdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *tcphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
					if(memcmp(&tcphdr->src, pos+4, 2) != 0){
						return -1;
					}
				}else if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV6, 2)==0){
					return -1; // TODO
				}else{
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_TCP_DST:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
					struct ip_hdr *iphdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *tcphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
					if(memcmp(&tcphdr->dest, pos+4, 2) != 0){
						return -1;
					}
				}else if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV6, 2)==0){
					return -1; // TODO
				}else{
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_UDP_SRC:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
					struct ip_hdr *iphdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *udphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
					if(memcmp(&udphdr->src, pos+4, 2) != 0){
						return -1;
					}
				}else if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV6, 2)==0){
					return -1; // TODO
				}else{
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_UDP_DST:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
					struct ip_hdr *iphdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *udphdr = (void*)(packet->data + oob->eth_type_offset + 2 + IPH_HL(iphdr) * 4);
					if(memcmp(&udphdr->dest, pos+4, 2) != 0){
						return -1;
					}
				}else if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV6, 2)==0){
					return -1; // TODO
				}else{
					return -1;
				}
				break;
				
				// SCTP_SRC
				// SCTP_DST
				
				case OFPXMT13_OFB_ICMPV4_TYPE:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)!=0){
					return -1;
				}else{
					struct ip_hdr *iphdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_PROTO(iphdr)!=1){
						return -1;
					}
					const uint8_t *hdr = (void*)(packet->data + oob->eth_type_offset + IPH_HL(iphdr) * 4);
					if(hdr[0] != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ICMPV4_CODE:
				if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)!=0){
					return -1;
				}else{
					struct ip_hdr *iphdr = (void*)(packet->data + oob->eth_type_offset + 2);
					if(IPH_PROTO(iphdr)!=1){
						return -1;
					}
					const uint8_t *hdr = (void*)(packet->data + oob->eth_type_offset + IPH_HL(iphdr) * 4);
					if(hdr[1] != pos[4]){
						return -1;
					}
				}
				break;
			}
		}
	}
	return count;
}

static void send_ofp13_packet_in(struct ofp13_packet_in base, struct fx_packet *packet, uint16_t max_len, uint8_t *send_bits){
	if(max_len == OFPCML13_NO_BUFFER || max_len > packet->length){
		max_len = packet->length;
	} // max_len is send_len
	
	char oxm[32];
	uint16_t oxm_length = 0;
	if(packet->in_port != 0){
		uint32_t f = htonl(OXM_OF_IN_PORT);
		memcpy(oxm+oxm_length, &f, 4);
		memcpy(oxm+oxm_length+4, &packet->in_port, 4);
		oxm_length += 8;
	}
	if(packet->metadata != 0){
		uint32_t f = htonl(OXM_OF_METADATA);
		memcpy(oxm+oxm_length, &f, 4);
		memcpy(oxm+oxm_length+4, &packet->metadata, 8);
		oxm_length += 12;
	}
	if(packet->tunnel_id != 0){
		uint32_t f = htonl(OXM_OF_TUNNEL_ID);
		memcpy(oxm+oxm_length, &f, 4);
		memcpy(oxm+oxm_length+4, &packet->tunnel_id, 8);
		oxm_length += 12;
	}
	uint16_t length = offsetof(struct ofp13_packet_in, match) + ALIGN8(4+oxm_length) + 2 + max_len;
	
	base.header.length = htons(length);
	base.total_len = htons(packet->length);
	base.match.length = htons(4 + oxm_length);
	
	memset(ofp_buffer, 0, length);
	memcpy(ofp_buffer, &base, sizeof(struct ofp13_packet_in));
	memcpy(ofp_buffer+offsetof(struct ofp13_packet_in, match)+4,
		oxm, oxm_length);
	memcpy(ofp_buffer+offsetof(struct ofp13_packet_in, match)+ALIGN8(4+oxm_length)+2,
		packet->data, max_len);
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

void check_ofp13_packet_in(){
	for(int i=0; i<MAX_BUFFERS; i++){
		struct fx_packet_in *pin = fx_packet_ins+i;
		if((pin->send_bits &~ 0x80) == 0){
			continue;
		}
		if(pin->valid_until - sys_get_ms() > 0x80000000U){
			if(pin->packet.malloced){
				free(pin->packet.data);
				pin->packet.data = NULL;
				pin->packet.malloced = false;
			}
			pin->send_bits = 0;
			continue;
		}
		struct ofp13_packet_in msg = {
			.header = {
				.version = 4,
				.type = OFPT13_PACKET_IN,
			},
			.buffer_id = pin->buffer_id,
			.total_len = pin->packet.length,
			.table_id = pin->table_id,
			.reason = pin->reason,
			.cookie = pin->cookie,
			.match = {
				.type = htons(OFPMT13_OXM),
			}
		};
		
		send_ofp13_packet_in(msg, &pin->packet, ntohs(pin->max_len), &pin->send_bits);
		if(pin->send_bits == 0 && pin->packet.malloced){
			free(pin->packet.data);
			pin->packet.data = NULL;
			pin->packet.malloced = false;
		}
	}
}

static void set_field(struct fx_packet *packet, struct fx_packet_oob *oob, const void *oxm){
	uint8_t *data = packet->data;
	const uint8_t *o = oxm;
	switch(ntohl(*(uint32_t*)oxm)){
		// OXM_OF_IN_PORT, OXM_OF_IN_PHY_PORT not valid by spec.
		// OXM_OF_METADATA not valid by spec.
		case OXM_OF_ETH_DST_W:
		for(int i=0; i<6; i++){
			data[i] &= ~o[10+i];
			data[i] |= o[4+i] & o[10+i];
		}
		break;
		
		case OXM_OF_ETH_DST:
		for(int i=0; i<6; i++){
			data[i] = o[4+i];
		}
		break;
		
		case OXM_OF_ETH_SRC_W:
		for(int i=0; i<6; i++){
			data[i+6] &= ~o[10+i];
			data[i+6] |= o[4+i] & o[10+i];
		}
		break;
		
		case OXM_OF_ETH_SRC:
		for(int i=0; i<6; i++){
			data[i+6] = o[4+i];
		}
		break;
		
		case OXM_OF_ETH_TYPE:
		{
			uint16_t i = oob->eth_type_offset;
			data[i] = o[4];
			data[i+1] = o[5];
		}
		break;
		
		case OXM_OF_VLAN_VID:
		if((oob->vlan[0] & 0x10) != 0){
			data[14] = (data[14] & 0xF0) | o[4];
			data[15] = o[5];
			memcpy(oob->vlan, data+14, 2);
		}
		
		// TODO: implement more
		
		// OXM_OF_IPV6_EXTDR not valid by spec.
	}
}

/*
 *	return false on fatal status
 */
static bool execute_ofp13_action(struct fx_packet *packet, struct fx_packet_oob *oob, void *action, int flow){
	struct ofp13_action_header act;
	memcpy(&act, action, sizeof(act));
	
	switch(ntohs(act.type)){
		case OFPAT13_OUTPUT:
		{
			struct ofp13_action_output out;
			memcpy(&out, action, sizeof(out));
			
			uint32_t in_port_idx = ntohl(packet->in_port)-1;
			uint32_t out_port_idx = ntohl(out.port) - 1; // port starts from 1
			if(out_port_idx < OFPP13_MAX){
				if(out.port != packet->in_port && out_port_idx<4 && Zodiac_Config.of_port[out_port_idx]==1){
					if(disable_ofp_pipeline == false){
						fx_port_counts[out_port_idx].tx_packets++;
						gmac_write(packet->data, packet->length, 1<<out_port_idx);
					}
				}
			}else if(out.port == htonl(OFPP13_ALL) || out.port == htonl(OFPP13_FLOOD) || out.port == htonl(OFPP13_NORMAL)){
				if(disable_ofp_pipeline == false){
					uint8_t p = 0;
					for(uint32_t i=0; i<MAX_PORTS; i++){
						if(Zodiac_Config.of_port[i]==1 && i != in_port_idx){
							p |= 1<<i;
							fx_port_counts[i].tx_packets++;
						}
					}
					if(p != 0){
						gmac_write(packet->data, packet->length, p);
					}
				}
			}else if(out.port == htonl(OFPP13_CONTROLLER)){
				uint8_t send_bits = 0;
				uint32_t buffer_id = htonl(OFP13_NO_BUFFER);
				if(out.max_len != htons(OFPCML13_NO_BUFFER)){
					send_bits |= 0x80;
					buffer_id = htonl(fx_buffer_id++);
				}
				
				uint8_t reason = OFPR13_ACTION;
				uint8_t table_id = 0;
				uint64_t cookie = 0xffffffffffffffffULL;
				if(flow >= 0){
					if(fx_flows[flow].priority == 0 && fx_flows[flow].oxm_length == 0){
						// table-miss
						reason = OFPR13_NO_MATCH;
					}
					table_id = fx_flows[flow].table_id;
					cookie = fx_flows[flow].cookie;
				}
				
				struct ofp13_packet_in msg = {
					.header = {
						.version = 4,
						.type = OFPT13_PACKET_IN,
					},
					.buffer_id = buffer_id,
					.total_len = htons(packet->length),
					.table_id = table_id,
					.reason = reason,
					.cookie = cookie,
					.match = {
						.type = htons(OFPMT13_OXM),
					}
				};
				
				for(int i=0; i<MAX_CONTROLLERS; i++){
					if(controllers[i].ofp.negotiated){
						send_bits |= 1<<i;
					}
				}
				send_ofp13_packet_in(msg, packet, ntohs(out.max_len), &send_bits);
				if(send_bits != 0){
					for(int i=0; i<MAX_BUFFERS; i++){
						struct fx_packet_in *pin = fx_packet_ins+i;
						if(pin->send_bits == 0){
							void *data = malloc(packet->length);
							if(data != NULL){
								memcpy(data, packet->data, packet->length);
								
								pin->buffer_id = msg.buffer_id;
								pin->reason = msg.reason;
								pin->table_id = msg.table_id;
								pin->cookie = msg.cookie;
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
			}
		}
		break;
		
		case OFPAT13_PUSH_VLAN:
		{
			struct ofp13_action_push ap;
			memcpy(&ap, action, sizeof(ap));
			
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
			memcpy(data+12, &ap.ethertype, 2);
			data[14] = oob->vlan[0] & 0xEF; // clear CFI
			data[15] = oob->vlan[1];
			
			packet->data = data;
			packet->length = length;
			sync_oob(packet, oob);
		}
		break;
		
		case OFPAT13_POP_VLAN:
		if((oob->vlan[0] & 0x10) != 0){ // CFI bit indicates VLAN_PRESENT
			uint8_t *data = packet->data;
			memmove(data+12, data+16, packet->length-16);
			packet->length -= 4;
			sync_oob(packet, oob);
		}
		break;
		
		case OFPAT13_SET_NW_TTL:
		if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
			struct ofp13_action_nw_ttl an;
			memcpy(&an, action, sizeof(an));
			
			struct ip_hdr *hdr = (void*)(packet->data + oob->eth_type_offset + 2);
			IPH_TTL_SET(hdr, an.nw_ttl);
		} // TODO: IPv6, MPLS
		break;
		
		case OFPAT13_DEC_NW_TTL:
		{
			bool notify = false;
			if(memcmp(packet->data + oob->eth_type_offset, ETH_TYPE_IPV4, 2)==0){
				struct ip_hdr *hdr = (void*)(packet->data + oob->eth_type_offset + 2);
				uint8_t ttl = IPH_TTL(hdr);
				if(ttl == 1){
					notify = true;
				} else {
					IPH_TTL_SET(hdr, ttl-1);
				}
			} // TODO: IPv6, MPLS

			if(notify){
				uint8_t send_bits = 0;
				uint64_t buffer_id = htonl(OFP13_NO_BUFFER);
				if(fx_switch.miss_send_len != OFPCML13_NO_BUFFER){
					send_bits |= 0x80;
					buffer_id = htonl(fx_buffer_id++);
				}
		
				uint8_t table_id = 0;
				uint8_t reason = OFPR13_INVALID_TTL;
				uint64_t cookie = 0xffffffffffffffffULL; // openvswitch does this
				if(flow >= 0){
					table_id = fx_flows[flow].table_id;
					cookie = fx_flows[flow].cookie;
				}

				struct ofp13_packet_in msg = {
					.header = {
						.version = 4,
						.type = OFPT13_PACKET_IN,
					},
					.buffer_id = buffer_id,
					.total_len = htons(packet->length),
					.table_id = table_id,
					.reason = reason,
					.cookie = cookie,
					.match = {
						.type = OFPMT13_OXM,
					}
				};
		
				for(int i=0; i<MAX_CONTROLLERS; i++){
					if(controllers[i].ofp.negotiated){
						send_bits |= 1<<i;
					}
				}
				send_ofp13_packet_in(msg, packet, fx_switch.miss_send_len, &send_bits);
				if(send_bits != 0){
					for(int i=0; i<MAX_BUFFERS; i++){
						struct fx_packet_in *pin = fx_packet_ins+i;
						if(pin->send_bits == 0){
							uint8_t *data = malloc(packet->length);
							if(data != NULL){
								pin->send_bits = send_bits;
								pin->valid_until = sys_get_ms() + BUFFER_TIMEOUT;
						
								pin->buffer_id = buffer_id;
								pin->reason = reason;
								pin->table_id = table_id;
								pin->cookie = cookie;
						
								struct fx_packet pkt = {
									.data = data,
									.length = packet->length,
									.capacity = packet->length,
									.malloced = true,
									.in_port = packet->in_port,
									.metadata = packet->metadata,
									.tunnel_id = packet->tunnel_id,
									.in_phy_port = packet->in_phy_port,
								};
								pin->packet = pkt;
						
								pin->max_len = fx_switch.miss_send_len;
								} else {
								// out of memory. silent drop.
							}
							break;
						}
					}
				}
			}
		}
		break;
		
		case OFPAT13_SET_FIELD:
		{
			struct ofp13_action_set_field as;
			memcpy(&as, action, sizeof(as));
			set_field(packet, oob, as.field);
		}
		break;
	}
	return true;
}

// 	OFPAT13_SET_FIELD has different rule
static const uint16_t actset_index[] = {
	OFPAT13_COPY_TTL_IN,
	OFPAT13_POP_VLAN,
	OFPAT13_POP_MPLS,
	OFPAT13_POP_PBB,
	OFPAT13_PUSH_MPLS,
	OFPAT13_PUSH_PBB,
	OFPAT13_PUSH_VLAN,
	OFPAT13_COPY_TTL_OUT,
	OFPAT13_DEC_MPLS_TTL,
	OFPAT13_DEC_NW_TTL,
	OFPAT13_SET_MPLS_TTL,
	OFPAT13_SET_NW_TTL,
	OFPAT13_SET_QUEUE,
	OFPAT13_GROUP,
	OFPAT13_OUTPUT,
};

void execute_ofp13_flow(struct fx_packet *packet, struct fx_packet_oob *oob, int flow){
	void* insts[8] = {0};
	uintptr_t pos = (uintptr_t)fx_flows[flow].ops;
	while(pos < (uintptr_t)fx_flows[flow].ops + fx_flows[flow].ops_length){
		struct ofp13_instruction hdr;
		memcpy(&hdr, (void*)pos, sizeof(hdr));
		
		uint16_t itype = ntohs(hdr.type);
		if(itype < 8){
			insts[itype] = (void*)pos;
		}
		pos += ntohs(hdr.len);
	}
	
	if(insts[OFPIT13_METER] != NULL){
		// todo
	}
	if(insts[OFPIT13_APPLY_ACTIONS] != NULL){
		struct ofp13_instruction_actions ia;
		memcpy(&ia, insts[OFPIT13_APPLY_ACTIONS], sizeof(ia));
		
		uintptr_t p = (uintptr_t)insts[OFPIT13_APPLY_ACTIONS] + offsetof(struct ofp13_instruction_actions, actions);
		while(p < (uintptr_t)insts[OFPIT13_APPLY_ACTIONS] + ntohs(ia.len)){
			struct ofp13_action_header act;
			memcpy(&act, (void*)p, sizeof(act));
			
			if(execute_ofp13_action(packet, oob, (void*)p, flow) == false){
				return;
			}
			p += ntohs(act.len);
		}
	}
	if(insts[OFPIT13_CLEAR_ACTIONS] != NULL){
		memset(oob->action_set, 0, sizeof(void *) * 16);
		if(oob->action_set_oxm != NULL){
			free(oob->action_set_oxm);
			oob->action_set_oxm = NULL;
		}
		oob->action_set_oxm_length = 0;
	}
	if(insts[OFPIT13_WRITE_ACTIONS] != NULL){
		struct ofp13_instruction_actions ia;
		memcpy(&ia, insts[OFPIT13_WRITE_ACTIONS], sizeof(ia));
		
		uintptr_t p = (uintptr_t)insts[OFPIT13_WRITE_ACTIONS] + offsetof(struct ofp13_instruction_actions, actions);
		while(p < (uintptr_t)insts[OFPIT13_WRITE_ACTIONS] + ntohs(ia.len)){
			struct ofp13_action_header act;
			memcpy(&act, (void*)p, sizeof(act));
			
			if(ntohs(act.type) == OFPAT13_SET_FIELD){
				struct ofp13_action_set_field setf;
				memcpy(&setf, (void*)p, sizeof(setf));
				// TODO: scan oob->action_set
			}else{
				for(uintptr_t i=0; i<sizeof(actset_index)/sizeof(uint16_t); i++){
					if(actset_index[i] == ntohs(act.type)){
						oob->action_set[i] = (void*)p;
					}
				}
			}
			p += ntohs(act.len);
		}
	}
	if(insts[OFPIT13_WRITE_METADATA] != NULL){
		struct ofp13_instruction_write_metadata iw;
		memcpy(&iw, insts[OFPIT13_WRITE_METADATA], sizeof(iw));
		
		packet->metadata &= ~iw.metadata_mask;
		packet->metadata |= (iw.metadata & iw.metadata_mask);
	}
	if(insts[OFPIT13_GOTO_TABLE] != NULL){
		struct ofp13_instruction_goto_table ig;
		memcpy(&ig, insts[OFPIT13_GOTO_TABLE], sizeof(ig));
		
		uint8_t table = ig.table_id;
		if(table < MAX_TABLES){
			flow = lookup_fx_table(packet, oob, table);
			fx_table_counts[table].lookup++;
			if(flow >= 0){
				if(fx_flows[flow].priority == 0 && fx_flows[flow].oxm_length == 0){
					// table-miss
				}else{
					fx_table_counts[table].matched++;
				}
				fx_flow_counts[flow].packet_count++;
				fx_flow_counts[flow].byte_count += packet->length;
				fx_flow_timeouts[flow].update = sys_get_ms();
				execute_ofp13_flow(packet, oob, flow);
			}
		}
		return;
	}
	// execute action set
	for(uintptr_t i=0; i<sizeof(actset_index)/sizeof(uint16_t); i++){
		if(oob->action_set[i] == NULL){
			continue;
		}
		if(execute_ofp13_action(packet, oob, oob->action_set[i], flow) == false){
			return;
		}
	}
}

enum ofp_pcb_status ofp13_handle(struct ofp_pcb *self){
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
		
		case OFPT13_FEATURES_REQUEST:
		if(ofp_tx_room(self) < 32){
			// noop
		} else if(length > 8){
			return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
		} else {
			struct ofp13_switch_features res = {
				.header = {
					.version = 4,
					.type = OFPT13_FEATURES_REPLY,
					.length = htons(32),
					.xid = req.xid,
				},
				.n_buffers = htonl(MAX_BUFFERS),
				.n_tables = MAX_TABLES,
				.capabilities = htonl(OFPC13_FLOW_STATS | OFPC13_TABLE_STATS | OFPC13_PORT_STATS),
			};
			char dpid[8] = {0};
			memcpy(dpid+2, Zodiac_Config.MAC_address, 6);
			memcpy(&res.datapath_id, dpid, 8);
			ofp_tx_write(self, &res, 32);
			ret = OFP_OK;
		}
		break;

		case OFPT13_GET_CONFIG_REQUEST:
		if(ofp_rx_length(self) < 8 || ofp_tx_room(self) < 12){
			// noop
		} else if(length > 8){
			return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
		} else {
			struct ofp13_switch_config res = {
				.header = {
					.version = 4,
					.type = OFPT13_GET_CONFIG_REPLY,
					.length = htons(12),
					.xid = req.xid,
				},
				.flags = htons(fx_switch.flags),
				.miss_send_len = htons(fx_switch.miss_send_len),
			};
			ofp_tx_write(self, &res, 12);
			ret = OFP_OK;
		}
		break;

		case OFPT13_SET_CONFIG:
		if(ofp_rx_length(self) < 12 || ofp_tx_room(self) < 12+64){
			// noop
		} else if(length > 12){
			return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
		} else {
			struct ofp13_switch_config msg;
			ofp_rx_read(self, &msg, 12);
			fx_switch.flags = ntohs(msg.flags); // XXX: add tcp_reass() support
			fx_switch.miss_send_len = ntohs(msg.miss_send_len);
			// XXX: ofp_error may be raised while setting the other fields
			ret = OFP_OK;
		}
		break;

		case OFPT13_PACKET_OUT:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			// noop
		} else if(length < 24){
			return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
		} else {
			struct ofp13_packet_out hint;
			pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp13_packet_out), self->rskip);
			
			void *actions = malloc(ntohs(hint.actions_len));
			if(actions == NULL){
				return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_EPERM);
			}
			
			struct fx_packet packet = {
				.in_port = hint.in_port,
			};
			if(hint.buffer_id != htonl(OFP13_NO_BUFFER)){
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
					return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BUFFER_UNKNOWN);
				}
				
				uint16_t offset = offsetof(struct ofp13_packet_out, actions);
				pbuf_copy_partial(self->rbuf, actions, ntohs(hint.actions_len), self->rskip+offset);
			}else{
				uint16_t len = offsetof(struct ofp13_packet_out, actions);
				len += ntohs(hint.actions_len);
				
				void *data = malloc(length-len);
				if(data == NULL){ // out-of memory
					free(actions);
					return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_EPERM);
				}
				
				uint16_t offset = offsetof(struct ofp13_packet_out, actions);
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
				struct ofp13_action_header act;
				memcpy(&act, (void*)p, sizeof(act));
				
				if(p + ntohs(act.len) > endp){
					free(actions);
					if(packet.malloced){
						free(packet.data);
					}
					return ofp_write_error(self, OFPET13_BAD_ACTION, OFPBAC13_BAD_LEN);
				}
				// xxx: check more
				p += ntohs(act.len);
			}
			p = (uintptr_t)actions;
			while(p < endp){
				struct ofp13_action_header act;
				memcpy(&act, (void*)p, sizeof(act));
				
				if(execute_ofp13_action(&packet, &oob, (void*)p, -1)==false){
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

		case OFPT13_FLOW_MOD:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			// noop
		} else {
			struct ofp13_flow_mod hint;
			pbuf_copy_partial(self->rbuf, &hint, sizeof(struct ofp13_flow_mod), self->rskip);
			uint16_t offset = offsetof(struct ofp13_flow_mod, match) + ALIGN8(ntohs(hint.match.length));
			uint16_t oxm_len = ntohs(hint.match.length) - 4;
			uint16_t ops_len = ntohs(hint.header.length) - offset;
			if(oxm_len > MAX_MATCH_LEN){
				// openflow send_flow_removed limitation
				return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
			}
			void *oxm = NULL;
			void *ops = NULL;
			
			if(oxm_len > 0){
				oxm = malloc(oxm_len);
				if(oxm == NULL){
					return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
				}
				offset = offsetof(struct ofp13_flow_mod, match) + 4;
				pbuf_copy_partial(self->rbuf, oxm, oxm_len, self->rskip + offset);
			}
			if(ops_len > 0){
				ops = malloc(ops_len);
				if(ops == NULL){
					if(oxm != NULL) free(oxm);
					return ofp_write_error(self, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
				}
				offset = offsetof(struct ofp13_flow_mod, match) + ALIGN8(ntohs(hint.match.length));
				pbuf_copy_partial(self->rbuf, ops, ops_len, self->rskip + offset);
			}

			ret = mod_ofp13_flow(self, oxm, oxm_len, ops, ops_len);
		}
		break;

		case OFPT13_GROUP_MOD:
			ret = mod_ofp13_group(self);
		break;

		case OFPT13_METER_MOD:
			ret = mod_ofp13_meter(self);
		break;

		default:
			if(ofp_tx_room(self) < 12+64){
				//noop
			}else{
				return ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_TYPE);
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

void timeout_ofp13_flows(){
	uint32_t send_bits = 0;
	for(int i=0; i<MAX_CONTROLLERS; i++){
		if(controllers[i].ofp.negotiated){
			send_bits |= 1<<i;
		}
	}
	for(int i=0; i<iLastFlow; i++){
		if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0){
			// already removed
			continue;
		}
		if(fx_flow_timeouts[i].hard_timeout != 0){
			uint32_t timeout = fx_flow_timeouts[i].init + fx_flow_timeouts[i].hard_timeout;
			if(timeout - sys_get_ms() > 0x80000000){
				if((fx_flows[i].flags & OFPFF13_SEND_FLOW_REM) != 0 ){
					fx_flows[i].send_bits = send_bits;
				} else {
					fx_flows[i].send_bits = 0;
				}
			}
		}
		if(fx_flow_timeouts[i].idle_timeout != 0){
			uint32_t timeout = fx_flow_timeouts[i].update + fx_flow_timeouts[i].idle_timeout;
			if(timeout - sys_get_ms() > 0x80000000){
				if((fx_flows[i].flags & OFPFF13_SEND_FLOW_REM) != 0 ){
					fx_flows[i].send_bits = send_bits;
				} else {
					fx_flows[i].send_bits = 0;
				}
			}
		}
	}
}

void send_ofp13_port_status(){
	for(int i=0; i<MAX_CONTROLLERS; i++){
		if(controllers[i].ofp.negotiated == false){
			continue;
		}
		uint8_t bits = 1<<i;
		for(int j=0; j<4; j++){
			uint8_t reason;
			if((fx_ports[j].send_bits & bits) != 0){
				if(Zodiac_Config.of_port[j] == 1){
					reason = OFPPR13_ADD;
				}else{
					reason = OFPPR13_DELETE;
				}
			}else if((fx_ports[j].send_bits_mod & bits) != 0){
				reason = OFPPR13_MODIFY;
			}else{
				continue;
			}
			if(ofp_tx_room(&controllers[i].ofp) > 80){
				struct ofp13_port_status msg = {
					.header = {
						.version = 4,
						.type = OFPT13_PORT_STATUS,
						.length = htons(80),
						.xid = htonl(controllers[i].ofp.xid++),
					},
					.reason = reason,
					.desc = {
						.port_no = htonl(i+1),
						.config = htonl(get_switch_config(j)),
						.state = htonl(get_switch_status(j)),
						.curr = htonl(get_switch_ofppf13_curr(j)),
						.advertised = htonl(get_switch_ofppf13_advertised(j)),
						.supported = htonl(	OFPPF13_COPPER | OFPPF13_PAUSE | OFPPF13_PAUSE_ASYM |OFPPF13_100MB_FD \
							| OFPPF13_100MB_HD | OFPPF13_10MB_FD | OFPPF13_10MB_HD | OFPPF13_AUTONEG),
						.peer = htonl(get_switch_ofppf13_peer(j)),
						.max_speed = htonl(100000u),
					},
				};
				ofp_tx_write(&controllers[i].ofp, &msg, 80);
				fx_ports[j].send_bits &= ~bits;
				fx_ports[j].send_bits_mod &= ~bits;
			}
		}
	}
}

void send_ofp13_flow_rem(){
	for(int i=0; i<iLastFlow; i++){
		if(fx_flows[i].send_bits == 0){
			continue;
		}
		if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) != 0){
			continue;
		}
		uint16_t length = offsetof(struct ofp13_flow_removed, match) + ALIGN8(4+fx_flows[i].oxm_length);
		if(length > OFP_BUFFER_LEN){ // XXX: todo - tcp output should be buffered?
			fx_flows[i].send_bits = 0;
			continue;
		}
		struct ofp13_flow_removed msg = {
			.header = {
				.version = 4,
				.type = OFPT13_FLOW_REMOVED,
				.length = htons(length),
			},
			.cookie = fx_flows[i].cookie,
			.priority = fx_flows[i].priority,
			.reason = fx_flows[i].reason,
			.table_id = fx_flows[i].table_id,
			.duration_sec = htonl((sys_get_ms64() - fx_flow_timeouts[i].init)/1000u),
			.duration_nsec = htonl((sys_get_ms64() - fx_flow_timeouts[i].init)%1000u * 1000000u),
			.idle_timeout = htons(fx_flow_timeouts[i].idle_timeout),
			.hard_timeout = htons(fx_flow_timeouts[i].hard_timeout),
			.packet_count = fx_flow_counts[i].packet_count,
			.byte_count = fx_flow_counts[i].byte_count,
			.match = {
				.type = htons(OFPMT13_OXM),
				.length = htons(4 + fx_flows[i].oxm_length),
			},
		};
		for(int j=0; j<MAX_CONTROLLERS; j++){
			uint8_t bit = 1<<i;
			if(controllers[j].ofp.tcp == NULL){
				fx_flows[i].send_bits &= ~bit;
			}
			if((fx_flows[i].send_bits & bit) == 0){
				continue;
			}
			if(controllers[j].ofp.negotiated){
				struct ofp_pcb *ofp = &controllers[j].ofp;
				if(ofp_tx_room(ofp) > length){
					msg.header.xid = htons(ofp->xid++);
					uint16_t offset = offsetof(struct ofp13_flow_removed, match) + 4;
					memcpy(ofp_buffer, &msg, offset);
					memcpy(ofp_buffer+offset, fx_flows[i].oxm, fx_flows[i].oxm_length);
					ofp_tx_write(ofp, ofp_buffer, length);
					fx_flows[i].send_bits &= ~bit;
				}
			}
		}
	}
}

