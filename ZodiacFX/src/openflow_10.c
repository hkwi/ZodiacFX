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

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int iLastFlow;
extern int OF_Version;

extern char ofp_buffer[OFP_BUFFER_LEN];
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

/*
 * scans flow table for matching flow
 */
static int filter_ofp10_flow(int first, struct ofp10_filter filter){
	for(int i=first; i<iLastFlow; i++){
		if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0){
			continue;
		}
		if (filter.table_id != 0xff && filter.table_id != fx_flows[i].table_id){
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

static uint16_t fill_ofp10_flow_stats(const struct ofp_flow_stats_request *req, int *mp_index, void *buffer, uint16_t capacity){
	struct ofp10_filter filter = {
		.out_port = req->out_port,
		.table_id = req->table_id,
		.tuple = req->match,
	};

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
		struct ofp_flow_stats stats = {
			.length = htons(offsetof(struct ofp_flow_stats, actions)+fx_flows[i].ops_length),
			.table_id = fx_flows[i].table_id,
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
		// struct ofp13_flow_stats(including ofp13_match)
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
		.tuple = req->match,
	};
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
		struct ofp_table_stats stat = {
			.table_id = i,
			.wildcards = OFPFW_ALL,
			.max_entries = fx_table_features[i].max_entries,
			.active_count = htonl(active),
			.matched_count = htonll(fx_table_counts[i].matched),
			.lookup_count = htonll(fx_table_counts[i].lookup),
		};
		memcpy(stat.name, fx_table_features[i].name, sizeof(stat));
		
		uintptr_t buf = (uintptr_t)buffer+length;
		memcpy((void*)buf, &stat, sizeof(stat));
		length += sizeof(stat);
	}
	if(complete){
		*mp_index = -1;
	}
	return length;
}

static void make_port_stats(uint16_t port, struct ofp10_port_stats *stats){
	uint16_t i = port - 1; // index starts from 0.
	sync_switch_port_counts(i);
	uint64_t duration = sys_get_ms64() - fx_ports[i].init;
	stats->port_no = htonl(port);
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
 *	@param port in host byte order
 */
static uint16_t fill_ofp10_port_stats(uint16_t port, int *mp_index, void *buffer, uint16_t capacity){
	struct ofp10_port_stats stat;
	if(port == OFPP_NONE){
		bool complete = true;
		uint16_t len = 0;
		for(int i=*mp_index; i<4; i++){
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
	}else{
		make_port_stats(port, &stat);
		memcpy(buffer, &stat, sizeof(stat));
		*mp_index = -1;
		return sizeof(stat);
	}
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
	char unit[MP_UNIT_MAXSIZE];
	
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
				struct ofp13_desc zodiac_desc = {
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
			{
				struct ofp_flow_stats_request hint;
				if(self->mp_out_index < 0){
					if(ofp_rx_length(self) < sizeof(hint)){ // sizeof(hint)
						return OFP_NOOP;
					}
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
					mpres.flags = htons(OFPMPF13_REPLY_MORE);
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
					mpres.flags = htons(OFPMPF13_REPLY_MORE);
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
					return ofp10_write_mp_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
				}
				struct ofp10_port_stats_request hint;
				self->mpreq_pos += ofp_rx_read(self, &hint, 8);
				
				uint16_t port_no = ntohs(hint.port_no);
				if(port_no <= OFPP_MAX || port_no == OFPP_NONE){
					uint16_t capacity = ofp_tx_room(self);
					if(capacity > OFP_BUFFER_LEN){
						capacity = OFP_BUFFER_LEN;
					}
					uint16_t unitlength = fill_ofp10_port_stats(port_no,
						&self->mp_out_index, ofp_buffer+12, capacity-12);
					mpres.flags = 0;
					if(self->mp_out_index >= 0){
						mpres.flags = htons(OFPSF_REPLY_MORE);
					}
					mpres.header.length = htons(12+unitlength);
					memcpy(ofp_buffer, &mpres, 12);
					ofp_tx_write(self, ofp_buffer, 12+unitlength);
				}else{
					return ofp10_write_mp_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
				}
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
					.type = htons(OFPET13_BAD_REQUEST),
					.code = htons(OFPBRC13_BAD_MULTIPART),
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
	return 0; // TODO
}

void execute_ofp10_flow(struct fx_packet *packet, struct fx_packet_oob *oob, int flow){
	return; // TODO
}
