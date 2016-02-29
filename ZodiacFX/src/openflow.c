/**
 * @file
 * openflow.c
 *
 * This file contains the main OpenFlow functions
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
#include "config_zodiac.h"
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "timers.h"

// Global variables
extern struct zodiac_config Zodiac_Config;

// Local Variables
int iLastFlow = 0;
int OF_Version = 0x00;

volatile bool disable_ofp_pipeline = false;

struct fx_switch_config fx_switch = {
	.flags = OFPC13_FRAG_NORMAL,
	.miss_send_len = 128,
};

/*
 * `ofp_buffer` len is a globally shared buffer,
 * which is only for temporary use.
 * Use cases:
 *  * Look ahead ofp_header with pbuf_partial_copy
 *  * Flatten pbuf and pass it to tcp_write()
 *    with TCP_WRITE_FLAG_COPY
 */
char ofp_buffer[OFP_BUFFER_LEN];

struct fx_port fx_ports[MAX_PORTS] = {};
struct fx_port_count fx_port_counts[MAX_PORTS] = {};

struct fx_table_count fx_table_counts[MAX_TABLES] = {};

uint32_t fx_buffer_id = 0; // incremental
struct fx_packet_in fx_packet_ins[MAX_BUFFERS] = {};

struct fx_flow fx_flows[MAX_FLOWS] = {};
struct fx_flow_timeout fx_flow_timeouts[MAX_FLOWS] = {};
struct fx_flow_count fx_flow_counts[MAX_FLOWS] = {};

struct fx_meter_band fx_meter_bands[MAX_METER_BANDS] = {}; // excluding slowpath, controller

static void cleanup_fx_flows(void){
	int found;
	do{
		found = -1;
		for(int i=0; i<iLastFlow; i++){
			if(fx_flows[i].send_bits == 0){
				if(fx_flows[i].oxm != NULL){
					free(fx_flows[i].oxm);
					fx_flows[i].oxm = NULL;
				}
				if(fx_flows[i].ops != NULL){
					free(fx_flows[i].ops);
					fx_flows[i].ops = NULL;
				}
				found = i;
				break;
			}
		}
		if(found >= 0 && iLastFlow>0){
			fx_flows[found] = fx_flows[iLastFlow-1];
			iLastFlow--;
		}else{
			break;
		}
	}while(found >= 0);
}

static void watch_fx_flows(void){
	if(OF_Version == 4){
		timeout_ofp13_flows();
		send_ofp13_flow_rem();
	}else{
		// TODO: ofp10 version should be placed here.
	}
	cleanup_fx_flows();
}

int lookup_fx_table(const struct fx_packet *packet, const struct fx_packet_oob *oob, uint8_t table_id){
	int found = -1;
	int score = -1;
	for(int i=0; i<iLastFlow; i++){
		if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0 || fx_flows[i].table_id != table_id){
			continue;
		}
		if(found>=0 && fx_flows[found].priority > fx_flows[i].priority){
			continue;
		}
		int s = -1;
		if(OF_Version == 4){
			s = match_frame_by_oxm(packet, oob, fx_flows[i].oxm, fx_flows[i].oxm_length);
		} else if(OF_Version == 1){
			s = match_frame_by_tuple(packet, oob, fx_flows[i].tuple);
		}
		if(s<0 || s<score){
			continue;
		}
		score = s;
		found = i;
	}
	return found;
}

static void ofp_unreach(void){
	// for breakpoint
	volatile uint32_t hook;
	while(1){ hook++; }
}

static void ofp_update(struct ofp_pcb *self){
	while(self->rbuf != NULL && self->rskip >= self->rbuf->len){
		struct pbuf *head = self->rbuf;
		self->rskip -= self->rbuf->len;
		self->rbuf = pbuf_dechain(head);
		pbuf_free(head);
	}
}

uint16_t ofp_rx_length(const struct ofp_pcb *self){
	if(self->rbuf == NULL) return 0;
	return self->rbuf->tot_len - self->rskip;
}

/*
 * `ofp_rx_read` pops bytes from ofp_pcb rx buffer
 * @return written length
 */
uint16_t ofp_rx_read(struct ofp_pcb *self, void *buf, uint16_t capacity){
	if(ofp_rx_length(self) < capacity){
		capacity = ofp_rx_length(self);
	}
	if(capacity == 0){
		return 0;
	}
	uint16_t ret = pbuf_copy_partial(self->rbuf, buf, capacity, self->rskip);
	self->rskip += ret;
	return ret;
}

uint16_t ofp_tx_room(const struct ofp_pcb *pcb){
	return tcp_sndbuf(pcb->tcp);
}

/*
 * `ofp_tx_write` writes into underlying tcp buffer.
 * writes ALL or NOTHING.
 * `data` will be queued as a single TCP segment, so you should write a
 * single complete openflow message in one call.
 */
uint16_t ofp_tx_write(struct ofp_pcb *pcb, const void *data, uint16_t length){
	if(ofp_tx_room(pcb) >= length){
		if(ERR_OK == tcp_write(pcb->tcp, data, length, TCP_WRITE_FLAG_COPY)){
			pcb->trigger_output = true;
			pcb->txlen += length;
			tcp_output(pcb->tcp);
			return length;
		}
	}
	return 0;
}

#define CONNECT_RETRY_INTERVAL 3000U /* 3 sec */
#define OFP_PING_INTERVAL 7000U // 7sec
#define OFP_TIMEOUT 60000U // 1 min

static err_t ofp_close(struct ofp_pcb *self, uint32_t sleep){
	struct tcp_pcb *tcp = self->tcp;
	while(self->rbuf != NULL){
		struct pbuf *head = self->rbuf;
		self->rbuf = pbuf_dechain(head);
		pbuf_free(head);
	}
	memset(self, 0, sizeof(struct ofp_pcb));
	self->sleep_until = sys_get_ms() + sleep;
	if(tcp != NULL){
		return tcp_close(tcp);
	}
	return ERR_OK;
}

/*
 * `ofp_write_error` consumes entire request message from ofp_pcb rx buffer.
 * so don't read from ofp_pcb when use call this.
 */
enum ofp_pcb_status ofp_write_error(struct ofp_pcb *self, uint16_t ofpet, uint16_t ofpec){
	if(ofp_rx_length(self) < 8){
		return OFP_NOOP;
	};
	struct ofp_header req;
	pbuf_copy_partial(self->rbuf, &req, 8, self->rskip);
	
	uint16_t length = ntohs(req.length);
	if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
		return OFP_NOOP;
	}

	uint16_t rlen = 12;
	struct ofp_error_msg err = {
		.header = {
			.version = OF_Version,
			.type = OFPT10_ERROR,
			.xid = req.xid,
		},
		.type = htons(ofpet),
		.code = htons(ofpec),
	};
	if(length < 8){
		rlen += 8;
		ofp_rx_read(self, ofp_buffer+12, 8);
	} else if(length > 64){
		rlen += 64;
		ofp_rx_read(self, ofp_buffer+12, 64);
		self->rskip += length - 64;
	} else {
		rlen += length;
		ofp_rx_read(self, ofp_buffer+12, length);
	}
	err.header.length = htons(rlen);
	memcpy(ofp_buffer, &err, 12);
	ofp_tx_write(self, ofp_buffer, rlen);
	if(length < 8){
		return OFP_CLOSE;
	}
	return OFP_OK;
}

static enum ofp_pcb_status ofp_negotiation(struct ofp_pcb *self){
	if(self->negotiated){
		return OFP_OK;
	}
	if(ofp_rx_length(self) < 8){
		return OFP_NOOP;
	}
	struct ofp_header req;
	pbuf_copy_partial(self->rbuf, &req, 8, self->rskip);
	if (req.type != OFPT10_HELLO){
		uint16_t length = ntohs(req.length);
		if(length > 64){
			length = 64; // at least 64 bytes from request by spec.
		}
		ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_VERSION);
		return OFP_CLOSE;
	}
	// we want to process this at one time
	uint16_t length = ntohs(req.length);
	if(ofp_rx_length(self) < length){
		return OFP_NOOP;
	}
	
	
	bool has_versionbitmap = false;
	uint32_t versionbitmap = 0;
	if(length > 8){
		uint16_t pos = 8;
		struct ofp13_hello_elem_header element = {0};
		while(pos < length){
			pbuf_copy_partial(self->rbuf, &element, 4, self->rskip+pos);
			if(ntohs(element.type) == OFPHET13_VERSIONBITMAP){
				// 1 or 4 is in the first bitmap
				has_versionbitmap = true;
				pbuf_copy_partial(self->rbuf, &versionbitmap, 4, self->rskip+pos+4);
				versionbitmap = ntohl(versionbitmap);
				break;
			}
			pos += ALIGN8(ntohs(element.length));
		}
	}
	int fixed_of_version = 0;
	if(switch_negotiated()){
		fixed_of_version = OF_Version;
	} else {
		fixed_of_version = Zodiac_Config.of_version;
	}
	if(fixed_of_version != 0){
		if(has_versionbitmap && (versionbitmap & (1<<fixed_of_version)) == 0){
			// no good
		}else if(req.version >= fixed_of_version){
			self->negotiated = true;
			OF_Version = fixed_of_version;
			self->rskip += length;
			return OFP_OK;
		}
	} else if(req.version == 4 || (has_versionbitmap && ((versionbitmap&0x10) != 0))){
		self->negotiated = true;
		OF_Version = 4;
		self->rskip += length;
		return OFP_OK;
	} else if(req.version == 1 || (has_versionbitmap && ((versionbitmap&0x02) != 0))){
		self->negotiated = true;
		OF_Version = 1;
		self->rskip += length;
		return OFP_OK;
	}
	// may add reason ASCII string as payload by spec
	ofp_write_error(self, OFPET10_HELLO_FAILED, OFPHFC_INCOMPATIBLE);
	return OFP_CLOSE;
}

static enum ofp_pcb_status ofp_multipart_complete(struct ofp_pcb *self){
	if(OF_Version == 4){
		return ofp13_multipart_complete(self);
	}
	return OFP_OK;
}


static void ofp_async(void){
	if(OF_Version == 4){
		send_ofp13_flow_rem();
		send_ofp13_port_status();
		check_ofp13_packet_in();
	}else{
		// TODO: ofp10 version should be placed here.
	}
	cleanup_fx_flows();
}

static enum ofp_pcb_status ofp_handle(struct ofp_pcb *self){
	enum ofp_pcb_status ret = ofp_negotiation(self);
	if(OFP_OK != ret){
		return ret;
	}
	ret = ofp_multipart_complete(self);
	if(OFP_OK != ret){
		return ret;
	}
	ofp_async();
	while(ofp_rx_length(self) >= 8){
		ret = OFP_NOOP;
		struct ofp_header req; // look ahead
		pbuf_copy_partial(self->rbuf, &req, 8, self->rskip);
		uint16_t length = ntohs(req.length);
		if(length < 8){
			ret = ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_LEN);
		} else if(req.type == OFPT10_ECHO_REQUEST){
			// we want to process this at one time
			if(ofp_rx_length(self) < length || ofp_tx_room(self) < 8){
				ret = OFP_NOOP;
			} else {
				self->rskip += length;
				struct ofp_header rep = {
					.version = OF_Version,
					.type = OFPT10_ECHO_REPLY,
					.length = htons(8),
					.xid = req.xid,
				};
				ofp_tx_write(self, &rep, 8);
				ret = OFP_OK;
			}
		} else if(req.type == OFPT10_ECHO_REPLY){
			// we want to process this at one time
			if(ofp_rx_length(self) < length){
				ret = OFP_NOOP;
			} else {
				self->rskip += length;
				// TODO: optionally measure the health here
				ret = OFP_OK;
			}
		} else if(req.version == 4){
			switch(req.type){
				case OFPT13_BARRIER_REQUEST:
				if(self->mpreq_on){
					ret = ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_MULTIPART_BUFFER_OVERFLOW);
				} else if(ofp_rx_length(self) < length || ofp_tx_room(self) < 8){
					ret = OFP_NOOP;
				} else {
					self->rskip += length;
					struct ofp_header rep = {
						.version = 4,
						.type = OFPT13_BARRIER_REPLY,
						.length = htons(8),
						.xid = req.xid,
					};
					ofp_tx_write(self, &rep, 8);
					ret = OFP_OK;
				}
				break;
				
				case OFPT13_MULTIPART_REQUEST:
				{
					struct ofp13_multipart_request mpreq;
					memcpy(&mpreq, self->mpreq_hdr, sizeof(struct ofp13_multipart_request));
					if(self->mpreq_on && req.xid != mpreq.header.xid){
						ret = ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_MULTIPART_BUFFER_OVERFLOW);
					} else if(length < 16 || length > 16+MP_UNIT_MAXSIZE){
						ofp_write_error(self, OFPET13_BAD_REQUEST, OFPBRC13_BAD_LEN);
						ret = OFP_CLOSE;
					} else if(ofp_tx_room(self) < 16){
						ret = OFP_NOOP;
					} else {
						ofp_rx_read(self, self->mpreq_hdr, 16);
						self->mpreq_on = true;
						self->mpreq_pos = 16;
						self->mp_out_index = -1;
						ret = ofp_multipart_complete(self);
					}
				}
				break;
				
				default:
					ret = ofp13_handle(self);
				break;
			}
		} else if(req.version == 1){
			// TODO: implement here
			ret = ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_TYPE);
		} else {
			ret = ofp_write_error(self, OFPET10_BAD_REQUEST, OFPBRC10_BAD_VERSION);
		}
		if(ret != OFP_OK){
			break;
		}
	}
	if (OFP_OK == ret){
		ofp_async();
	}
	return ret;
}

static err_t ofp_poll_cb(void *arg, struct tcp_pcb *pcb){
	struct ofp_pcb *ofp = arg;
	if(ofp->tcp != pcb){
		tcp_abort(pcb);
		return ERR_ABRT;
	}
	if(ofp->alive_until - sys_get_ms() > 0x80000000U){
		return ofp_close(ofp, CONNECT_RETRY_INTERVAL);
	}
	if(ofp->negotiated && ofp->next_ping - sys_get_ms() > 0x80000000U){
		ofp->next_ping = sys_get_ms() + OFP_PING_INTERVAL;
		if(ofp_tx_room(ofp) > 8) {
			struct ofp_header hdr = {
				.version = OF_Version,
				.type = OFPT10_ECHO_REQUEST,
				.length = htons(8),
				.xid = htonl(ofp->xid++),
			};
			ofp_tx_write(ofp, &hdr, 8);
			return tcp_output(ofp->tcp);
		}
	}
	if(ofp->negotiated){
		ofp_async();
	}
	return ERR_OK;
}

static err_t ofp_sent_cb(void *arg, struct tcp_pcb *tcp, u16_t len){
	struct ofp_pcb *ofp = arg;
	if(ofp->tcp != tcp){ // maybe manually closed
		tcp_abort(tcp);
		return ERR_ABRT;
	}
	ofp->txlen -= len;
	ofp->alive_until = sys_get_ms() + OFP_TIMEOUT;
	switch(ofp_handle(ofp)){
		case OFP_OK:
			tcp_output(ofp->tcp);
			break;
		case OFP_CLOSE:
			tcp_output(ofp->tcp);
			return ofp_close(ofp, CONNECT_RETRY_INTERVAL);
	}
	ofp_update(ofp);
	return ERR_OK;
}

static err_t ofp_recv_cb(void *arg, struct tcp_pcb *tcp, struct pbuf *p, err_t err){
	struct ofp_pcb *ofp = arg;
	if(ofp->tcp != tcp){ // maybe manually closed
		if(p != NULL){
			pbuf_free(p);
		}
		tcp_abort(tcp);
		return ERR_ABRT;
	}
	if (p == NULL){
		return ofp_close(ofp, CONNECT_RETRY_INTERVAL);
	}
	if(ERR_IS_FATAL(err)){
		pbuf_free(p);
		return ofp_close(ofp, CONNECT_RETRY_INTERVAL);
	}
	
	// there are very limited number of POOL mem
	struct pbuf *n = pbuf_alloc(PBUF_RAW, p->tot_len, PBUF_RAM);
	if(n != NULL){
		// not pbuf_copy because p was queue
		pbuf_copy_partial(p, ofp_buffer, p->tot_len, 0);
		pbuf_take(n, ofp_buffer, p->tot_len);
		pbuf_free(p);
		tcp_recved(tcp, p->tot_len);
		if(ofp->rbuf == NULL){
			ofp->rbuf = n;
		}else{
			pbuf_chain(ofp->rbuf, n);
		}
	}
	ofp->alive_until = sys_get_ms() + OFP_TIMEOUT;
	switch(ofp_handle(ofp)){
		case OFP_OK:
			tcp_output(ofp->tcp);
			break;
		case OFP_CLOSE:
			tcp_output(ofp->tcp);
			return ofp_close(ofp, CONNECT_RETRY_INTERVAL);
	}
	ofp_update(ofp);
	if(n == NULL){
		return ERR_BUF;
	}
	return ERR_OK;
}

static err_t ofp_connected_cb(void *arg, struct tcp_pcb *tcp, err_t err){
	struct ofp_pcb *ofp = arg;
	if(ofp->tcp != tcp){
		tcp_abort(tcp);
		return ERR_ABRT;
	}
	if(ERR_IS_FATAL(err)){
		memset(ofp, 0, sizeof(struct ofp_pcb));
		return err;
	}
	err_t ret;
	ofp->alive_until = sys_get_ms() + OFP_TIMEOUT;
	ofp->next_ping = sys_get_ms() + OFP_PING_INTERVAL;
	if (Zodiac_Config.of_version == 1){
		struct ofp_header hdr = {
			.version = 1,
			.type = OFPT10_HELLO,
			.length = htons(8),
			.xid = htonl(ofp->xid++),
		};
		ret = ofp_tx_write(ofp, &hdr, 8);
	} else if (Zodiac_Config.of_version == 4){
		// XXX: add hello elements for negotiation
		struct ofp_header hdr = {
			.version = 4,
			.type = OFPT13_HELLO, // same with OFPT10_HELLO
			.length = htons(8),
			.xid = htonl(ofp->xid++),
		};
		ret = ofp_tx_write(ofp, &hdr, 8);
	} else {
		// XXX: add hello elements for negotiation
		struct ofp_header hdr = {
			.version = MAX_OFP_VERSION,
			.type = OFPT13_HELLO, // same with OFPT10_HELLO
			.length = htons(8),
			.xid = htonl(ofp->xid++),
		};
		ret = ofp_tx_write(ofp, &hdr, 8);
	}
	if (ret == OFP_OK){
		return tcp_output(ofp->tcp);
	}
	return ret;
}

// tcp_err_fn
static void ofp_err_cb(void *arg, err_t err){
	if(arg == NULL) return;
	struct ofp_pcb *self = arg;
	if(err==ERR_RST){
		while(self->rbuf != NULL){
			struct pbuf *head = self->rbuf;
			self->rbuf = pbuf_dechain(head);
			pbuf_free(head);
		}
		memset(self, 0, sizeof(struct ofp_pcb));
		self->sleep_until = sys_get_ms() + CONNECT_RETRY_INTERVAL;
	} else if(err==ERR_ABRT){
		// tcp_abort will only be called outside of ofp context
	} else {
		ofp_unreach();
	}
}

struct controller controllers[MAX_CONTROLLERS] = {};

bool switch_negotiated(void){
	for(int i=0; i<MAX_CONTROLLERS; i++){
		if(controllers[i].ofp.negotiated){
			return true;
		}
	}
	return false;
}

#define PORT_STATUS_UPDATE_INTERVAL 1000u
static uint32_t update_port_status_next_ms = PORT_STATUS_UPDATE_INTERVAL;
#define PORT_COUNTS_UPDATE_INTERVAL 7000u
static uint32_t update_port_counts_next_ms = PORT_COUNTS_UPDATE_INTERVAL;
static uint8_t update_port_counts_next_no = 0;
static void update_fx_ports(void){
	// Recommendation was read every 30 sec; counters are designed as "read clear".
	if(update_port_counts_next_ms - sys_get_ms() > 0x80000000u){
		update_port_counts_next_ms = sys_get_ms() + PORT_COUNTS_UPDATE_INTERVAL;
		sync_switch_port_counts(update_port_counts_next_no);
		update_port_counts_next_no++;
		update_port_counts_next_no %= 4;
	}
	if(update_port_status_next_ms - sys_get_ms() > 0x80000000u){
		update_port_status_next_ms = sys_get_ms() + PORT_STATUS_UPDATE_INTERVAL;
		for(int i=0; i<4; i++){
			if(Zodiac_Config.of_port[i] == 1){
				uint8_t state = get_switch_status(i);
				if(fx_ports[i].state != state){
					fx_ports[i].state = state;
				
					uint8_t send_bits = 0;
					for(int j=0; j<MAX_CONTROLLERS; j++){
						if(controllers[j].ofp.negotiated){
							send_bits |= 1<<j;
						}
					}
					fx_ports[i].send_bits_mod = send_bits;
				}
			}
		}
		if(OF_Version == 4){
			send_ofp13_port_status();
		}else{
			// TODO:
		}
	}
}

void openflow_init(){
	IP4_ADDR(&controllers[0].addr,
		Zodiac_Config.OFIP_address[0],
		Zodiac_Config.OFIP_address[1],
		Zodiac_Config.OFIP_address[2],
		Zodiac_Config.OFIP_address[3]);
	for(int i=0; i<MAX_CONTROLLERS; i++){
		controllers[i].ofp.sleep_until = sys_get_ms();
	}
}

void openflow_task(){
	update_fx_ports();
	watch_fx_flows();
	for(int i=0; i<MAX_CONTROLLERS; i++){
		struct controller *c = &controllers[i];
		// no-address, or connected, or sleeping
		if(c->addr.addr == 0){
			continue;
		}
		if(c->ofp.tcp != NULL) {
			if(c->ofp.trigger_output){
				tcp_output(c->ofp.tcp);
				c->ofp.trigger_output = false;
			}
			continue;
		}
		if(c->ofp.sleep_until - sys_get_ms() < 0x80000000U) {
			continue;
		}
		struct tcp_pcb *tcp = tcp_new();
		if (tcp == NULL){
			c->ofp.sleep_until = sys_get_ms() + CONNECT_RETRY_INTERVAL;
			continue;
		}
		c->ofp.alive_until = sys_get_ms() + CONNECT_RETRY_INTERVAL;
		tcp_arg(tcp, &(c->ofp));
		tcp_err(tcp, ofp_err_cb);
		tcp_recv(tcp, ofp_recv_cb);
		tcp_sent(tcp, ofp_sent_cb);
		tcp_poll(tcp, ofp_poll_cb, 1); // need to be placed here for catching the very first SYN send failure
		tcp_connect(tcp, &(c->addr), Zodiac_Config.OFPort, ofp_connected_cb);
		c->ofp.tcp = tcp;
	}
}

/*
 *	update oob cache information
 */
void sync_oob(struct fx_packet *packet, struct fx_packet_oob *oob){
	const uint8_t *data = packet->data;
	uint8_t offset = 12;
	memset(oob->vlan, 0, 2);
	
	if(memcmp(data+offset, ETH_TYPE_VLAN, 2)==0 || memcmp(data+offset, ETH_TYPE_VLAN2, 2)==0){
		// save outer-most information
		memcpy(oob->vlan, data+14, 2);
		oob->vlan[0] |= 0x10; // CFI bit for VLAN_PRESENT
		offset += 4;
	}
	while(offset + 4 <= packet->length){
		if(memcmp(data+offset, ETH_TYPE_VLAN, 2)==0 || memcmp(data+offset, ETH_TYPE_VLAN2, 2)==0){
			offset += 4;
		}else{
			break;
		}
	}
	oob->eth_type_offset = offset;
}

void openflow_pipeline(struct fx_packet *packet){
	// we don't have to check the minimum length here,
	// because frame length is 60 or longer by ethernet spec.
	struct fx_packet_oob oob = {
		.action_set = {0},
		.action_set_oxm = NULL,
		.action_set_oxm_length = 0,
	};
	sync_oob(packet, &oob);
	
	// trim ethernet padding - may make this configurable
	if(packet->length == 60){
		const uint8_t *eth_type = packet->data + oob.eth_type_offset;
		if(memcmp(eth_type, ETH_TYPE_IPV4, 2)==0){
			struct ip_hdr *iphdr = (void*)(eth_type + 2);
			packet->length = oob.eth_type_offset + 2 + ntohs(IPH_LEN(iphdr));
		}
	}
	
	int flow = lookup_fx_table(packet, &oob, 0);
	fx_table_counts[0].lookup++;
	if(flow < 0){
		if(OF_Version==1){
			// XXX: packet-in
		}
		return;
	}
	if(OF_Version == 4 && fx_flows[flow].priority == 0 && fx_flows[flow].oxm_length == 0){
		// table-miss flow entry
	} else {
		fx_table_counts[0].matched++;
	}
	fx_flow_counts[flow].packet_count++;
	fx_flow_counts[flow].byte_count += packet->length;
	fx_flow_timeouts[flow].update = sys_get_ms();
	if(OF_Version == 4){
		execute_ofp13_flow(packet, &oob, flow);
	} else if(OF_Version == 1){
		execute_ofp10_flow(packet, &oob, flow);
	}
}
