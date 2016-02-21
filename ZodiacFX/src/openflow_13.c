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
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>
#include <lwip/udp.h>
#include "command.h"
#include "openflow.h"
#include "switch.h"
#include "timers.h"

// Global variables
extern struct zodiac_config Zodiac_Config;
extern struct tcp_pcb *tcp_pcb;
extern int OF_Version;
extern int iLastFlow;
extern int totaltime;
extern struct flows_counter flow_counters[MAX_FLOWS];
extern struct ofp13_port_stats phys13_port_stats[4];
extern struct table_counter table_counters;
extern uint8_t port_status[4];
extern struct ofp_switch_config Switch_config;
extern uint8_t shared_buffer[2048];
extern int delay_barrier;
extern uint32_t barrier_xid;
extern int multi_pos;

struct ofp13_flow_mod flow_match13[MAX_FLOWS];
char *ofp13_oxm_match[MAX_FLOWS];
char *ofp13_oxm_inst[MAX_FLOWS];

// Internal functions
void features_reply13(uint32_t xid);
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code);
void set_config13(struct ofp_header * msg);
void config_reply13(uint32_t xid);
void role_reply13(struct ofp_header *msg);
void flow_mod13(struct ofp_header *msg);
void flow_add13(struct ofp_header *msg);
void flow_delete13(struct ofp_header *msg);
void flow_delete_strict13(struct ofp_header *msg);
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portstats_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request * req);
int multi_table_reply13(uint8_t *buffer, struct ofp13_multipart_request *req);
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg);
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason);
void packet_out13(struct ofp_header *msg);

/*
*	Converts a 64bit value from host to network format
*
*	@param n - value to convert.
*
*/
static inline uint64_t (htonll)(uint64_t n)
{
	return HTONL(1) == 1 ? n : ((uint64_t) HTONL(n) << 32) | HTONL(n >> 32);
}

void nnOF13_tablelookup(char *p_uc_data, uint32_t *ul_size, int port)
{
	uint16_t eth_prot;
	memcpy(&eth_prot, p_uc_data + 12, 2);
	uint16_t packet_size;
	memcpy(&packet_size, ul_size, 2);
	uint16_t vlantag = htons(0x8100);
				
	if (Zodiac_Config.OFEnabled == OF_ENABLED) // Main lookup
	{
		table_counters.lookup_count++;
		
		int i = -1;
		// Check if packet matches an existing flow
		i = flowmatch13(p_uc_data, port);
		if (i == -2) return;	// Error packet
		if (i == -1) return;	// No match
		
		if ( i > -1)
		{
			flow_counters[i].hitCount++; // Increment flow hit count
			flow_counters[i].bytes += packet_size;
			flow_counters[i].lastmatch = totaltime; // Increment flow hit count
			table_counters.matched_count++;
			
			struct ofp13_instruction_actions *inst_actions;
			struct ofp13_action_header *act_hdr;
			struct ofp13_instruction *inst_ptr; 
			inst_ptr = (struct ofp13_instruction *) ofp13_oxm_inst[i];
			int inst_size = ntohs(inst_ptr->len);
			if(ntohs(inst_ptr->type) == OFPIT13_APPLY_ACTIONS)
			{
				int act_size = 0;
				while (act_size < (inst_size - sizeof(struct ofp13_instruction_actions)))
				{
					inst_actions  = ofp13_oxm_inst[i] + act_size;
					act_hdr = &inst_actions->actions;
					if (htons(act_hdr->type) == OFPAT13_OUTPUT)
					{
						struct ofp13_action_output *act_output = act_hdr;
						if (htonl(act_output->port) < OFPP13_MAX)
						{
							int outport = (1<< (ntohl(act_output->port)-1));
							gmac_write(p_uc_data, packet_size, outport);
						} else if (htonl(act_output->port) == OFPP13_CONTROLLER)
						{
							int pisize = ntohs(act_output->max_len);
							if (pisize > packet_size) pisize = packet_size;
							packet_in13(p_uc_data, pisize, port, OFPR_ACTION);
						} else if (htonl(act_output->port) == OFPP13_FLOOD)
						{
							int outport = 7 - (1<< (ntohl(act_output->port)-1));	// Need to fix this, may also send out the Non-OpenFlow port
							gmac_write(p_uc_data, packet_size, outport);
						}
					}
					if (htons(act_hdr->type) == OFPAT13_SET_FIELD)
					{
						struct ofp13_action_set_field *act_set_field = act_hdr;
						struct oxm_header13 oxm_header;
						uint16_t oxm_value16;
						uint32_t oxm_value32;
						memcpy(&oxm_header, act_set_field->field,4);
						oxm_header.oxm_field = oxm_header.oxm_field >> 1;		
						switch(oxm_header.oxm_field)
						{
							case OFPXMT13_OFB_VLAN_VID:
							memcpy(&oxm_value16, act_set_field->field + sizeof(struct oxm_header13), 2);
							uint16_t vlan_vid = (oxm_value16 - 0x10);
							uint16_t action_vlanid  = act_hdr;
							uint16_t pcp;
							uint16_t vlanid;
							uint16_t vlanid_mask = htons(0x0fff);
						
							if (eth_prot == vlantag)
							{
								memcpy(pcp, p_uc_data + 14, 2);
							} else {
								pcp = 0;
							}
							if (vlan_vid == 0xffff)
							{
								vlanid = pcp & ~vlanid_mask;
							} else {
									vlanid = (vlan_vid & vlanid_mask) | (pcp & ~vlanid_mask);
							}						
							// Does the packet have a VLAN header?
							if (eth_prot == vlantag)
							{
								if (vlan_vid == 0)	// If the packet has a tag but the action is to set it to 0 then remove it
								{
									memmove(p_uc_data + 12, p_uc_data + 16, packet_size - 16);
									packet_size -= 4;
									memcpy(ul_size, &packet_size, 2);
								} else {
									memcpy(p_uc_data + 14, &vlanid, 2);
								}
							} else {
								if (vlan_vid > 0)		// Only add the tag if the VLAN ID is greater then 0
								{
									memmove(p_uc_data + 16, p_uc_data + 12, packet_size - 12);
									memcpy(p_uc_data + 12, &vlantag,2);
									memcpy(p_uc_data + 14, &vlanid, 2);
									packet_size += 4;
									memcpy(ul_size, &packet_size, 2);
								}
							}				
							break;
							
							
						};													
					}								
					act_size += htons(act_hdr->len);
				}
			}
		}
	}
	return;
}

void of13_message(struct ofp_header *ofph, int size, int len)
{
	struct ofp13_multipart_request *multi_req;	
	switch(ofph->type)
	{
		case OFPT13_FEATURES_REQUEST:
		features_reply13(ofph->xid);
		break;
		
		case OFPT13_SET_CONFIG:
		set_config13(ofph);
		break;
		
		case OFPT13_GET_CONFIG_REQUEST:
		config_reply13(ofph->xid);
		break;

		case OFPT13_ROLE_REQUEST:
		role_reply13(ofph);
		break;
				
		case OFPT13_FLOW_MOD:
		flow_mod13(ofph);
		break;
				
		case OFPT13_MULTIPART_REQUEST:
		multi_req  = (struct ofp13_multipart_request *) ofph;
		if ( ntohs(multi_req->type) == OFPMP13_DESC )
		{
			multi_pos += multi_desc_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_PORT_STATS )
		{
			multi_pos += multi_portstats_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_PORT_DESC )
		{
			multi_pos += multi_portdesc_reply13(&shared_buffer[multi_pos], multi_req);
		}

		if ( htons(multi_req->type) == OFPMP13_TABLE_FEATURES )
		{
			multi_pos += multi_tablefeat_reply13(&shared_buffer[multi_pos], multi_req);
		}
		
		if ( ntohs(multi_req->type) == OFPMP13_TABLE )
		{
			multi_pos += multi_table_reply13(&shared_buffer[multi_pos], multi_req);
		}

		if ( ntohs(multi_req->type) == 	OFPMP13_FLOW )
		{
			multi_pos += multi_flow_reply13(&shared_buffer[multi_pos], multi_req);
		}		

		break;

		case OFPT10_PACKET_OUT:
		packet_out13(ofph);
		break;
				
		case OFPT13_BARRIER_REQUEST:
		if (size == len) {
			barrier13_reply(ofph->xid);
			delay_barrier = 0;
			} else {
			barrier_xid = ofph->xid;
			delay_barrier = 1;
		}
		break;
	};
	
	if (size == len)
	{
		sendtcp(&shared_buffer, multi_pos);
	}
	return;
}

/*
*	OpenFlow FEATURE Reply message function
*
*	@param xid - transaction ID
*
*/
void features_reply13(uint32_t xid)
{
	uint64_t datapathid = 0;
	int numofports = 0;
	for(int n=0;n<4;n++)
	{
		if(Zodiac_Config.of_port[n]==1)numofports++;
	}
	struct ofp13_switch_features features;
	uint8_t buf[256];
	int bufsize = sizeof(struct ofp13_switch_features);
	features.header.version = OF_Version;
	features.header.type = OFPT13_FEATURES_REPLY;
	features.header.length = HTONS(bufsize);
	features.header.xid = xid;
	memcpy(&datapathid, &Zodiac_Config.MAC_address, 6);
	features.datapath_id = datapathid << 16;
	features.n_buffers = htonl(0);		// Number of packets that can be buffered
	features.n_tables = 1;		// Number of flow tables
	features.capabilities = htonl(OFPC13_FLOW_STATS + OFPC13_TABLE_STATS + OFPC13_PORT_STATS);	// Switch Capabilities
	features.auxiliary_id = 0;	// Primary connection

	memcpy(&buf, &features, sizeof(struct ofp13_switch_features));
	sendtcp(&buf, bufsize);
	return;
}

/*
*	OpenFlow SET CONFIG message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void set_config13(struct ofp_header *msg)
{
	struct ofp_switch_config * sc;
	sc = (struct ofp_switch_config *) msg;
	memcpy(&Switch_config, sc, sizeof(struct ofp_switch_config));
	return;
}

/*
*	OpenFlow CONFIG Reply message function
*
*	@param xid - transaction ID
*
*/
void config_reply13(uint32_t xid)
{
	struct ofp13_switch_config cfg_reply;
	cfg_reply.header.version = OF_Version;
	cfg_reply.header.type = OFPT13_GET_CONFIG_REPLY;
	cfg_reply.header.xid = xid;
	cfg_reply.header.length = HTONS(sizeof(cfg_reply));
	cfg_reply.flags = OFPC13_FRAG_NORMAL;
	cfg_reply.miss_send_len = htons(256);	// Only sending the first 256 bytes
	sendtcp(&cfg_reply, sizeof(cfg_reply));
	return;
}

/*
*	OpenFlow SET CONFIG message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void role_reply13(struct ofp_header *msg)
{
	struct ofp13_role_request role_request;
	memcpy(&role_request, msg, sizeof(struct ofp13_role_request));
	role_request.header.type = OFPT13_ROLE_REPLY;
	sendtcp(&role_request, sizeof(struct ofp13_role_request));
	return;
}

/*
*	OpenFlow Multi-part DESCRIPTION reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_desc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	static struct ofp13_desc zodiac_desc = {
		.mfr_desc = "Northbound Networks",
		.hw_desc  = "Zodiac-FX Rev.A",
		.sw_desc  = VERSION,
		.serial_num= "none",
		.dp_desc  = "World's smallest OpenFlow switch!"
	};
	struct ofp13_multipart_reply *reply;
	uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_desc);
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_DESC);
	memcpy(reply->body, &zodiac_desc, sizeof(zodiac_desc));
	return len;
}

/*
*	OpenFlow Multi-part PORT Description reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_portdesc_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	int numofports = 0;
	for(int n=0;n<4;n++)
	{
		if(Zodiac_Config.of_port[n]==1) numofports++;
	}
	struct ofp13_multipart_reply *reply;
	struct ofp13_port phys_port[numofports];
	uint16_t len = sizeof(struct ofp13_multipart_reply) + sizeof(phys_port);
	int j = 0;
	char portname[8];
	reply = (struct ofp13_multipart_reply *) buffer;	
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_PORT_DESC);
	 
	uint8_t mac[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	update_port_status();		//update port status
	
	for(int l = 0; l< 4; l++)
	{
		if(Zodiac_Config.of_port[l] == 1)
		{
			phys_port[j].port_no = htonl(l+1);
			for(int k = 0; k<6; k++)            // Generate random MAC address
			{
				int r = rand() % 255;
				memset(mac + k,r,1);
			}
			memcpy(&phys_port[j].hw_addr, mac, sizeof(mac));
			memset(phys_port[j].name, 0, OFP13_MAX_PORT_NAME_LEN);	// Zero out the name string
			sprintf(portname, "eth%d",l);
			strcpy(phys_port[j].name, portname);
			phys_port[j].config = 0;
			if (port_status[j] == 1) phys_port[j].state = htonl(OFPPS13_LIVE);
			if (port_status[j] == 0) phys_port[j].state = htonl(OFPPS13_LINK_DOWN);
			phys_port[j].curr = htonl(OFPPF13_100MB_FD + OFPPF13_COPPER);
			phys_port[j].advertised = 0;
			phys_port[j].supported = 0;
			phys_port[j].peer = 0;
			phys_port[j].curr_speed = 0;
			phys_port[j].max_speed = 0;
			j ++;
		}
	}
	
	memcpy(reply->body, &phys_port[0],sizeof(phys_port));
	return len;	
}


/*
*	OpenFlow Multi-part TABLE reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_table_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	// XXX: no multi table support for now
	int len = offsetof(struct ofp13_multipart_reply, body) + sizeof(struct ofp13_table_stats);
	struct ofp13_multipart_reply *reply = buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.length = htons(len);
	reply->header.xid = msg->header.xid;
	reply->type = htons(OFPMP13_TABLE);
	reply->flags = 0;
	struct ofp13_table_stats *stats = reply->body;
	stats->table_id = 0;
	uint32_t active = 0;
	for(int i=0; i<iLastFlow; i++) {
		if (flow_counters[i].active){
			active++;
		}
	}
	stats->active_count = htonl(active);
	stats->matched_count = htonll(table_counters.matched_count);
	stats->lookup_count = htonll(table_counters.lookup_count);
	return len;
}

/*
*	OpenFlow Multi-part TABLE Features reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_tablefeat_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	struct ofp13_multipart_reply *reply;
	struct ofp13_table_features tbl_feats;
	struct ofp13_table_feature_prop_instructions inst_prop;
	struct ofp13_instruction inst;
	struct oxm_header13 oxm_header;
	int prop_size = (14*8);

	char tablename[OFP13_MAX_TABLE_NAME_LEN];		
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_TABLE_FEATURES);
	
	tbl_feats.table_id = 100;
	sprintf(tablename, "table_100");
	strcpy(tbl_feats.name, tablename);	
	tbl_feats.metadata_match = 0;
	tbl_feats.metadata_write = 0;
	tbl_feats.config = 0;
	tbl_feats.max_entries = htonl(MAX_FLOWS);
	int len = sizeof(struct ofp13_multipart_reply) + sizeof(struct ofp13_table_features) + prop_size; 
	reply->header.length = htons(len);
	tbl_feats.length = htons(sizeof(struct ofp13_table_features) + prop_size);
	memcpy(reply->body, &tbl_feats, sizeof(struct ofp13_table_features));
			
	// Instruction Property	
 	inst_prop.type = htons(OFPTFPT13_INSTRUCTIONS);
 	inst_prop.length = htons(8);
 	inst.type = htons(OFPIT13_APPLY_ACTIONS);
 	inst.len = htons(4);
	memcpy(buffer + (len-(prop_size)), &inst_prop, 4);
	memcpy(buffer + (len-(prop_size-4)), &inst, 4);	 
	// Next Table Property
	inst_prop.type = htons(OFPTFPT13_NEXT_TABLES);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-8)), &inst_prop, 4);
	// Write Actions Property
	inst_prop.type = htons(OFPTFPT13_WRITE_ACTIONS);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-16)), &inst_prop, 4);
	// Apply Actions Property
	inst_prop.type = htons(OFPTFPT13_APPLY_ACTIONS);
	inst_prop.length = htons(8);
 	inst.type = htons(OFPAT13_OUTPUT);
 	inst.len = htons(4);
	memcpy(buffer + (len-(prop_size-24)), &inst_prop, 4);
	memcpy(buffer + (len-(prop_size-28)), &inst, 4);	
	// Match Property
	inst_prop.type = htons(OFPTFPT13_MATCH);
	inst_prop.length = htons(52);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-32)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IN_PORT << 1;		
	memcpy(buffer + (len-(prop_size-36)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_ETH_DST << 1;
	memcpy(buffer + (len-(prop_size-40)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_ETH_SRC << 1;
	memcpy(buffer + (len-(prop_size-44)), &oxm_header, 4);	
	oxm_header.oxm_field = OFPXMT13_OFB_ETH_TYPE << 1;
	memcpy(buffer + (len-(prop_size-48)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_VLAN_VID << 1;
	memcpy(buffer + (len-(prop_size-52)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IP_PROTO << 1;
	memcpy(buffer + (len-(prop_size-56)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IPV4_SRC << 1;
	memcpy(buffer + (len-(prop_size-60)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IPV4_DST << 1;
	memcpy(buffer + (len-(prop_size-64)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_TCP_SRC << 1;
	memcpy(buffer + (len-(prop_size-68)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_TCP_DST << 1;
	memcpy(buffer + (len-(prop_size-72)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_UDP_SRC << 1;
	memcpy(buffer + (len-(prop_size-76)), &oxm_header, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_UDP_DST << 1;
	memcpy(buffer + (len-(prop_size-80)), &oxm_header, 4);
	// Wildcard Property
	inst_prop.type = htons(OFPTFPT13_WILDCARDS);
	inst_prop.length = htons(8);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-88)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_IN_PORT << 1;
	memcpy(buffer + (len-(prop_size-92)), &oxm_header, 4);			
	// Write set field Property
	inst_prop.type = htons(OFPTFPT13_WRITE_SETFIELD);
	inst_prop.length = htons(4);
	memcpy(buffer + (len-(prop_size-96)), &inst_prop, 4);
	// Apply set field Property
	inst_prop.type = htons(OFPTFPT13_APPLY_SETFIELD);
	inst_prop.length = htons(8);
	oxm_header.oxm_class = htons(0x8000);
	oxm_header.oxm_len = 4;
	memcpy(buffer + (len-(prop_size-104)), &inst_prop, 4);
	oxm_header.oxm_field = OFPXMT13_OFB_VLAN_VID << 1;		
	memcpy(buffer + (len-(prop_size-108)), &oxm_header, 4);		

	return len;
}

/*
*	OpenFlow Multi-part FLOW reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_flow_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	char statsbuffer[2048];
	struct ofp13_multipart_reply *reply;
	reply = (struct ofp13_multipart_reply *) buffer;
	reply->header.version = OF_Version;
	reply->header.type = OFPT13_MULTIPART_REPLY;
	reply->header.xid = msg->header.xid;
	reply->flags = 0;
	reply->type = htons(OFPMP13_FLOW);	
	int len = flow_stats_msg13(&statsbuffer, 0, iLastFlow);
	memcpy(reply->body, &statsbuffer, len);
	len += 	sizeof(struct ofp13_multipart_reply);
	reply->header.length = htons(len);		

	return len;
}

/*
*	OpenFlow Multi-part PORT Stats reply message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
int multi_portstats_reply13(uint8_t *buffer, struct ofp13_multipart_request *msg)
{
	struct ofp13_port_stats zodiac_port_stats[3];
	struct ofp13_multipart_reply reply;
	struct ofp13_port_stats_request *port_req = msg->body;
	int stats_size = 0;
	int k, len;
	uint32_t port = ntohl(port_req->port_no);

	if (port == OFPP13_ANY)
	{
		stats_size = (sizeof(struct ofp13_port_stats) * 3);	// Assumes 3 ports
		len = sizeof(struct ofp13_multipart_reply) + stats_size;
		
		reply.header.version = OF_Version;
		reply.header.type = OFPT13_MULTIPART_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPMP13_PORT_STATS);
		reply.flags = 0;
		
		for(k=0; k<3;k++)
		{
			zodiac_port_stats[k].port_no = htonl(k+1);
			zodiac_port_stats[k].rx_packets = htonll(phys13_port_stats[k].rx_packets);
			zodiac_port_stats[k].tx_packets = htonll(phys13_port_stats[k].tx_packets);
			zodiac_port_stats[k].rx_bytes = htonll(phys13_port_stats[k].rx_bytes);
			zodiac_port_stats[k].tx_bytes = htonll(phys13_port_stats[k].tx_bytes);
			zodiac_port_stats[k].rx_crc_err = htonll(phys13_port_stats[k].rx_crc_err);
			zodiac_port_stats[k].rx_dropped = htonll(phys13_port_stats[k].rx_dropped);
			zodiac_port_stats[k].tx_dropped = htonll(phys13_port_stats[k].tx_dropped);
			zodiac_port_stats[k].rx_frame_err = 0;
			zodiac_port_stats[k].rx_over_err = 0;
			zodiac_port_stats[k].tx_errors = 0;
			zodiac_port_stats[k].rx_errors = 0;
			zodiac_port_stats[k].collisions = 0;
			
		}
		memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
		memcpy(buffer+sizeof(struct ofp13_multipart_reply), &zodiac_port_stats[0], stats_size);
	} else if (port <= OFPP13_MAX) {
		stats_size = sizeof(struct ofp13_port_stats);
		len = sizeof(struct ofp13_multipart_reply) + stats_size;
		
		reply.header.version = OF_Version;
		reply.header.type = OFPT13_MULTIPART_REPLY;
		reply.header.length = htons(len);
		reply.header.xid = msg->header.xid;
		reply.type = htons(OFPMP13_PORT_STATS);
		reply.flags = 0;

		zodiac_port_stats[port].port_no = htonl(port);
		zodiac_port_stats[port].rx_packets = htonll(phys13_port_stats[port-1].rx_packets);
		zodiac_port_stats[port].tx_packets = htonll(phys13_port_stats[port-1].tx_packets);
		zodiac_port_stats[port].rx_bytes = htonll(phys13_port_stats[port-1].rx_bytes);
		zodiac_port_stats[port].tx_bytes = htonll(phys13_port_stats[port-1].tx_bytes);
		zodiac_port_stats[port].rx_crc_err = htonll(phys13_port_stats[port-1].rx_crc_err);
		zodiac_port_stats[port].rx_dropped = htonll(phys13_port_stats[port-1].rx_dropped);
		zodiac_port_stats[port].tx_dropped = htonll(phys13_port_stats[port-1].tx_dropped);
		zodiac_port_stats[port].rx_frame_err = 0;
		zodiac_port_stats[port].rx_over_err = 0;
		zodiac_port_stats[port].tx_errors = 0;
		zodiac_port_stats[port].rx_errors = 0;
		zodiac_port_stats[port].collisions = 0;

		memcpy(buffer, &reply, sizeof(struct ofp13_multipart_reply));
		memcpy(buffer+sizeof(struct ofp13_multipart_reply), &zodiac_port_stats[port], stats_size);
	}
	return len;
}

/*
*	Main OpenFlow FLOW_MOD message function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_mod13(struct ofp_header *msg)
{
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;

	switch(ptr_fm->command)
	{
		case OFPFC13_ADD:
		flow_add13(msg);
		break;
		
		case OFPFC_MODIFY:
		//flow_modify13(msg);
		break;
		
		case OFPFC_MODIFY_STRICT:
		//flow_modify_strict13(msg);
		break;
		
		case OFPFC13_DELETE:
		flow_delete13(msg);
		break;
		
		case OFPFC13_DELETE_STRICT:
		flow_delete_strict13(msg);
		break;
	}
	return;
}

/*
*	OpenFlow FLOW_ADD function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_add13(struct ofp_header *msg)
{
	
	if (iLastFlow > (MAX_FLOWS-1))
	{
		of_error13(msg, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		return;
	}
	
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;
	memcpy(&flow_match13[iLastFlow], ptr_fm, sizeof(struct ofp13_flow_mod));
	if (ntohs(ptr_fm->match.length) > 4)
	{
		ofp13_oxm_match[iLastFlow] = malloc(ntohs(flow_match13[iLastFlow].match.length)-4);	// Allocate a space to store match fields
		memcpy(ofp13_oxm_match[iLastFlow], ptr_fm->match.oxm_fields, ntohs(flow_match13[iLastFlow].match.length)-4);
	} else {
		ofp13_oxm_match[iLastFlow] = NULL;
	}
	int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
	int instruction_size = ntohs(ptr_fm->header.length) - mod_size;
	if (instruction_size > 0)
	{
		ofp13_oxm_inst[iLastFlow] = malloc(instruction_size);	// Allocate a space to store instructions and actions
		uint8_t *inst_ptr = (uint8_t *)ptr_fm + mod_size;
		memcpy(ofp13_oxm_inst[iLastFlow], inst_ptr, instruction_size);
	} else {
		ofp13_oxm_inst[iLastFlow] = NULL;
	}	
			
	flow_counters[iLastFlow].duration = totaltime;
	flow_counters[iLastFlow].lastmatch = totaltime;
	flow_counters[iLastFlow].active = true;
	iLastFlow++;
	return;
}

void flow_delete13(struct ofp_header *msg)
{
	struct ofp13_flow_mod *ptr_fm = msg;
	for(int q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if (ptr_fm->table_id != OFPTT13_ALL && ptr_fm->table_id != flow_match13[q].table_id)
				{
						continue;
				}
				if (ptr_fm->cookie_mask != 0 && ptr_fm->cookie != (flow_match13[q].cookie & ptr_fm->cookie_mask))
				{
						continue;
				}
				if (ptr_fm->out_port != OFPP13_ANY)
				{
						bool out_port_match = false;
						int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
						int instruction_size = ntohs(flow_match13[q].header.length) - mod_size;
						struct ofp13_instruction *inst;
						for(inst=ofp13_oxm_inst[q]; inst<ofp13_oxm_inst[q]+instruction_size; inst+=inst->len)
						{
								if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
								{
									struct ofp13_instruction_actions *ia = inst;
									struct ofp13_action_header *action;
									for(action=ia->actions; action<inst+inst->len; action+=action->len)
									{
										if(action->type==OFPAT13_OUTPUT)
										{
											struct ofp13_action_output *output = action;
											if (output->port == ptr_fm->out_port)
											{
												out_port_match = true;
											}
									}
								}
						}
				}
					if(out_port_match==false)
					{
						continue;
					}
				}
				if (ptr_fm->out_group != OFPG13_ANY)
				{
					bool out_group_match = false;
					int mod_size = ALIGN8(offsetof(struct ofp13_flow_mod, match) + ntohs(ptr_fm->match.length));
					int instruction_size = ntohs(flow_match13[q].header.length) - mod_size;
					struct ofp13_instruction *inst;
					for(inst=ofp13_oxm_inst[q]; inst<ofp13_oxm_inst[q]+instruction_size; inst+=inst->len)
					{
						if(inst->type == OFPIT13_APPLY_ACTIONS || inst->type == OFPIT13_WRITE_ACTIONS)
						{
							struct ofp13_instruction_actions *ia = inst;
							struct ofp13_action_header *action;
							for(action=ia->actions; action<inst+inst->len; action+=action->len)
							{
								if(action->type==OFPAT13_GROUP)
								{
									struct ofp13_action_group *group = action;
									if (group->group_id == ptr_fm->out_group)
									{
										out_group_match = true;
									}
								}
							}
						}
								}
								if(out_group_match==false)
								{
										continue;
								}
						}
						if(field_match13(ofp13_oxm_match[q], ntohs(flow_match13[q].match.length)-4, ptr_fm->match.oxm_fields, ntohs(ptr_fm->match.length)-4) == 0)
						{
								continue;
						}
						if (ptr_fm->flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(q,OFPRR_DELETE);
						// Clear the counters and action
						memset(&flow_counters[q], 0, sizeof(struct flows_counter));
						if(ofp13_oxm_match[q] != NULL)
						{
								free(ofp13_oxm_match[q]);
						}
						if(ofp13_oxm_inst[q] != NULL)
						{
								free(ofp13_oxm_inst[q]);
						}
				}
		}
	
		int flow_count = 0;
		for(int q=0;q<iLastFlow;q++)
		{
			if (flow_counters[q].active){
			if (flow_count != q) {
			memcpy(&flow_counters[flow_count], &flow_counters[q], sizeof(struct flows_counter));
			ofp13_oxm_match[flow_count] = ofp13_oxm_match[q];
			ofp13_oxm_inst[flow_count] = ofp13_oxm_inst[q];
			}
			flow_count++;
		}
	}
	iLastFlow = flow_count;
	return;
}

/*
*	OpenFlow FLOW Delete Strict function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void flow_delete_strict13(struct ofp_header *msg)
{
	struct ofp13_flow_mod * ptr_fm;
	ptr_fm = (struct ofp13_flow_mod *) msg;
	int q;
	
	for(q=0;q<iLastFlow;q++)
	{
		if(flow_counters[q].active == true)
		{
			if((memcmp(&flow_match13[q].match, &ptr_fm->match, sizeof(struct ofp13_match)) == 0) && (memcmp(&flow_match13[q].cookie, &ptr_fm->cookie,4) == 0))
			{
				if (ptr_fm->flags &  OFPFF_SEND_FLOW_REM) flowrem_notif(q,OFPRR_DELETE);
				// Clear the counters and action
				memset(&flow_counters[q], 0, sizeof(struct flows_counter));
				if(ofp13_oxm_match[q] != NULL)
				{
						free(ofp13_oxm_match[q]);
				}
				if(ofp13_oxm_inst[q] != NULL)
				{
						free(ofp13_oxm_inst[q]);
				}
			}
		}
	}
	int flow_count = 0;
	for(int q=0;q<iLastFlow;q++)
	{
		if (flow_counters[q].active){
			if (flow_count != q) {
				memcpy(&flow_counters[flow_count], &flow_counters[q], sizeof(struct flows_counter));
				ofp13_oxm_match[flow_count] = ofp13_oxm_match[q];
				ofp13_oxm_inst[flow_count] = ofp13_oxm_inst[q];
			}
			flow_count++;
		}
	}
	iLastFlow = flow_count;
	return;
}

/*
*	OpenFlow PACKET_IN function
*
*	@param *buffer - pointer to the buffer containing the packet.
*	@param ul_size - size of the packet.
*	@param *buffer - port that the packet was received on.
*	@param reason - reason for the packet in.
*
*/
void packet_in13(uint8_t *buffer, uint16_t ul_size, uint8_t port, uint8_t reason)
{
	uint16_t size = 0;
	struct ofp13_packet_in * pi;	
	uint16_t send_size = ul_size;
	struct oxm_header13 oxm_header;	
	uint32_t in_port = ntohl(port);
	
	if(tcp_sndbuf(tcp_pcb) < (send_size + 34)) return;

	pi = (struct ofp13_packet_in *) shared_buffer;
	pi->header.version = OF_Version;
	pi->header.type = OFPT13_PACKET_IN;
	pi->header.xid = 0;
	pi->buffer_id = -1;
	pi->reason = reason;
	pi->table_id = 0;
	pi->cookie = -1;

	pi->match.type = htons(OFPMT13_OXM);
	pi->match.length = htons(12);
	oxm_header.oxm_class = ntohs(0x8000);
	oxm_header.oxm_field = OFPXMT13_OFB_IN_PORT;
	oxm_header.oxm_len = 4;
	memcpy(shared_buffer + sizeof(struct ofp13_packet_in)-4, &oxm_header, 4);
	memcpy(shared_buffer + sizeof(struct ofp13_packet_in), &in_port, 4);
 	size = sizeof(struct ofp13_packet_in) + 10 + send_size;	
	pi->header.length = HTONS(size);
	pi->total_len = HTONS(send_size);
	memcpy(shared_buffer + (size-send_size), buffer, send_size);
	sendtcp(&shared_buffer, size);
	tcp_output(tcp_pcb);
	return;
}

/*
*	OpenFlow PACKET_OUT function
*
*	@param *msg - pointer to the OpenFlow message.
*
*/
void packet_out13(struct ofp_header *msg)
{
	uint32_t outPort = 0;
	struct ofp13_packet_out * po;
	po = (struct ofp13_packet_out *) msg;
	uint32_t inPort = htonl(po->in_port);
	uint8_t *ptr = (uint8_t *) po;
	int size = ntohs(po->header.length) - ((sizeof(struct ofp13_packet_out) + ntohs(po->actions_len)));	
	ptr += sizeof(struct ofp13_packet_out) + ntohs(po->actions_len);
	if (size < 0) return; // Corrupt packet!
	struct ofp13_action_header *act_hdr = po->actions;
	if (ntohs(act_hdr->type) == OFPAT13_OUTPUT)	
	{
		struct ofp13_action_output *act_out = act_hdr;
		outPort = htonl(act_out->port);
	}
	
	if (outPort == OFPP13_FLOOD)
	{
		outPort = 7 - (1 << (inPort-1));	// Need to fix this, may also send out the Non-OpenFlow port
		} else {
		outPort = 1 << (outPort-1);
	}
	gmac_write(ptr, size, outPort);
	return;
}

/*
*	OpenFlow BARRIER Reply message function
*
*	@param xid - transaction ID
*
*/
void barrier13_reply(uint32_t xid)
{
	struct ofp_header of_barrier;
	of_barrier.version= OF_Version;
	of_barrier.length = htons(sizeof(of_barrier));
	of_barrier.type   = OFPT13_BARRIER_REPLY;
	of_barrier.xid = xid;
	sendtcp(&of_barrier, sizeof(of_barrier));
	return;
}

/*
*	OpenFlow ERROR message function
*
*	@param *msg - pointer to the OpenFlow message.
*	@param - error type.
*	@param - error code.
*
*/
void of_error13(struct ofp_header *msg, uint16_t type, uint16_t code)
{
	// get the size of the message, we send up to the first 64 back with the error
	int msglen = htons(msg->length);
	if (msglen > 64) msglen = 64;
	char error_buf[96];
	struct ofp_error_msg error;
	error.header.type = OFPT13_ERROR;
	error.header.version = OF_Version;
	error.header.length = htons(sizeof(struct ofp_error_msg) + msglen);
	error.header.xid = msg->xid;
	error.type = htons(type);
	error.code = htons(code);
	memcpy(error_buf, &error, sizeof(struct ofp_error_msg));
	memcpy(error_buf + sizeof(struct ofp_error_msg), msg, msglen);
	sendtcp(&error_buf, (sizeof(struct ofp_error_msg) + msglen));
	return;
}



// --- kwi --- //
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
	const char *oxm;
};

/*
 * scans flow table for matching flow
 */
int filter_ofp13_flow(int first, struct ofp13_filter filter){
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
			const char *ops = fx_flows[i].ops;
			while(ops < fx_flows[i].ops+fx_flows[i].ops_length){
				struct ofp13_instruction inst;
				memcpy(&inst, ops, sizeof(struct ofp13_instruction));
				if(inst.type==htons(OFPIT13_APPLY_ACTIONS) || inst.type==htons(OFPIT13_WRITE_ACTIONS)){
					struct ofp13_instruction_actions ia;
					memcpy(&ia, ops, sizeof(struct ofp13_instruction_actions));
					const char *act = (const char*)ia.actions;
					while(act < ops+ntohs(inst.len)){
						struct ofp13_action_header action;
						memcpy(&action, act, sizeof(struct ofp13_action_header));
						if(action.type==htons(OFPAT13_OUTPUT)){
							struct ofp13_action_output output;
							memcpy(&output, act, sizeof(struct ofp13_action_output));
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
			const char *ops = fx_flows[i].ops;
			while(ops < fx_flows[i].ops+fx_flows[i].ops_length){
				const struct ofp13_instruction *inst = (struct ofp13_instruction*)ops;
				if(inst->type==htons(OFPIT13_APPLY_ACTIONS) || inst->type==htons(OFPIT13_WRITE_ACTIONS)){
					struct ofp13_instruction_actions *ia = (struct ofp13_instruction_actions*)inst;
					const char *act = (const char*)ia->actions;
					while(act < ops+ntohs(inst->len)){
						const struct ofp13_action_header *action = (struct ofp13_action_header*)act;
						if(action->type==htons(OFPAT13_GROUP)){
							const struct ofp13_action_group *group = (struct ofp13_action_group*)action;
							if (group->group_id == filter.out_group){
								out_group_match = true;
							}
						}
						act += ntohs(action->len);
					}
				}
				ops += ntohs(inst->len);
			}
			if(out_group_match==false){
				continue;
			}
		}
		return i;
	}
	return -1;
}

static uint16_t fill_ofp13_flow_stats(const struct ofp13_flow_stats_request *unit, int *mp_index, char *buffer, uint16_t capacity){
	struct ofp13_filter filter = {
		.cookie = unit->cookie,
		.cookie_mask = unit->cookie_mask,
		.out_group = ntohl(unit->out_group),
		.out_port = ntohl(unit->out_port),
		.table_id = unit->table_id,
		.oxm_length = ntohs(unit->match.length)-4,
		.oxm = unit->match.oxm_fields,
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
		// struct ofp13_flow_stats(including ofp13_match)
		memcpy(buffer+length, &stats, sizeof(struct ofp13_flow_stats));
		// oxm_fields
		len = offsetof(struct ofp13_flow_stats, match) + offsetof(struct ofp13_match, oxm_fields);
		memcpy(buffer+length+len, fx_flows[i].oxm, fx_flows[i].oxm_length);
		// instructions
		len = offset_inst;
		memcpy(buffer+length+len, fx_flows[i].ops, fx_flows[i].ops_length);
		length += offset_inst + fx_flows[i].ops_length;
	}
	if(complete){
		*mp_index = -1; // complete
	}
	return length;
}

static uint16_t fill_ofp13_aggregate_stats(const struct ofp13_aggregate_stats_request *unit, int *mp_index, char *buffer, uint16_t capacity){
	if(capacity < 24){
		return 0;
	}
	struct ofp13_filter filter = {
		.cookie = unit->cookie,
		.cookie_mask = unit->cookie_mask,
		.out_group = ntohl(unit->out_group),
		.out_port = ntohl(unit->out_port),
		.table_id = unit->table_id,
		.oxm_length = ntohs(unit->match.length)-4,
		.oxm = unit->match.oxm_fields,
	};
	struct ofp13_aggregate_stats_reply res = {};
	for(int i=filter_ofp13_flow(*mp_index, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		res.packet_count += fx_flow_counts[i].packet_count;
		res.byte_count += fx_flow_counts[i].byte_count;
		res.flow_count++;
	}
	memcpy(buffer, &res, 24);
	*mp_index = -1;
	return 24;
}

static uint16_t fill_ofp13_table_stats(int *mp_index, char *buffer, uint16_t capacity){
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
		memcpy(buffer+length, &stat, 24);
		length += 24;
	}
	if(complete){
		*mp_index = -1;
	}
	return length;
}

static struct ofp13_port_stats make_port_stats(uint32_t port){
	sync_switch_port_counts(port);
	uint64_t duration = sys_get_ms64() - fx_ports[port].init;
	struct ofp13_port_stats stat = {
		.port_no = htonl(port+1),
		.rx_packets = htonll(fx_port_counts[port].rx_packets),
		.tx_packets = htonll(fx_port_counts[port].tx_packets),
		.rx_bytes = htonll(fx_port_counts[port].rx_bytes),
		.tx_bytes = htonll(fx_port_counts[port].tx_bytes),
		.rx_dropped = htonll(fx_port_counts[port].rx_dropped),
		.tx_dropped = htonll(fx_port_counts[port].tx_dropped),
		.rx_errors = htonll(fx_port_counts[port].rx_errors),
		.tx_errors = htonll(fx_port_counts[port].tx_errors),
		.rx_frame_err = htonll(fx_port_counts[port].rx_frame_err),
		.rx_over_err = htonll(fx_port_counts[port].rx_over_err),
		.rx_crc_err = htonll(fx_port_counts[port].rx_crc_err),
		.collisions = htonll(fx_port_counts[port].collisions),
		.duration_sec = htonl(duration/1000u),
		.duration_nsec = htonl((duration%1000u)*1000000u),
	};
	return stat;
}

static uint16_t fill_ofp13_port_stats(uint32_t port, int *mp_index, char *buffer, uint16_t capacity){
	uint32_t port_index = ntohl(port)-1;
	struct ofp13_port_stats stat;
	if(port_index < OFPP13_MAX){
		stat = make_port_stats(port_index);
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
				stat = make_port_stats(i);
				memcpy(buffer+len, &stat, 112);
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

static uint16_t fill_ofp13_port_desc(int *mp_index, char *buffer, uint16_t capacity){
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
			sprintf(port.name, "eth%d", i);
			if((curr & (OFPPF13_100MB_FD|OFPPF13_100MB_HD)) != 0){
				port.curr_speed = htonl(100000u);
			} else if((curr & (OFPPF13_10MB_FD|OFPPF13_10MB_HD)) != 0){
				port.curr_speed = htonl(10000u);
			}
			memcpy(buffer+length, &port, 64);
			length += 64;
		}
	}
	if(complete){
		*mp_index = -1;
	}
	return length;
}

enum ofp_pcb_status ofp13_multipart_complete(struct ofp_pcb *self){
	struct ofp13_multipart_request mpreq = {};
	struct ofp13_multipart_reply mpres = {};
	memcpy(&mpreq, self->mpreq_hdr, 16);
	memcpy(&mpres, self->mpreq_hdr, 16);
	mpres.header.type = OFPT13_MULTIPART_REPLY;
	uint16_t length = ntohs(mpreq.header.length);
	char unit[MP_UNIT_MAXSIZE];
	
	while(self->mpreq_pos != 0){
		switch(ntohs(mpreq.type)){
			case OFPMP13_DESC:
			if(ofp_rx_length(self) < length - self->mpreq_pos || ofp_tx_room(self) < 16+1056){
				return OFP_NOOP;
			}else{
				self->mpreq_pos += ofp_rx_read(self, ofp_buffer, length - self->mpreq_pos); // safety
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
				memcpy(&unit, self->mp_in, offsetof(struct ofp13_flow_stats_request, match) + ALIGN8(ntohs(hint.match.length)));
				uint16_t unitlength = fill_ofp13_flow_stats(
					(struct ofp13_flow_stats_request*)unit,
					&self->mp_out_index, ofp_buffer+16, ofp_tx_room(self)-16);
				mpres.flags = 0;
				if(self->mp_out_index >= 0){
					mpres.flags = htons(OFPMPF13_REPLY_MORE);
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
				uint16_t unitlength = fill_ofp13_aggregate_stats(
					(struct ofp13_aggregate_stats_request*)unit,
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
				struct ofp13_port_stats_request hint;
				self->mpreq_pos += ofp_rx_read(self, &hint, 8);
				memcpy(ofp_buffer, self->mpreq_hdr, 16);
				memcpy(ofp_buffer, &hint, 8);
				self->mpreq_pos += ofp_rx_read(self, ofp_buffer+24, length - self->mpreq_pos);
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
					ofp_set_error(ofp_buffer, OFPET13_BAD_REQUEST, OFPBRC13_BAD_PORT);
				}
			}
			break;
			
			case OFPMP13_PORT_DESC:
			if(ofp_tx_room(self) < 64){
				return OFP_NOOP;
			} else {
				if(self->mp_out_index < 0){
					self->mp_out_index = 0;
				}
				self->mpreq_pos += ofp_rx_read(self, ofp_buffer, length - self->mpreq_pos);
				uint16_t unitlength = fill_ofp13_port_desc(
					&self->mp_out_index, ofp_buffer+16, ofp_tx_room(self)-16);
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
				
				if (length > 64){
					length = 64;
				}
				char reply[12+64];
				struct ofp_error_msg err = {};
				err.header.version = mpreq.header.version;
				err.header.type = OFPT13_ERROR;
				err.header.length = htons(12+length);
				err.header.xid = mpreq.header.xid;
				err.type = htons(OFPET13_BAD_REQUEST);
				err.code = htons(OFPBRC13_BAD_MULTIPART);
				memcpy(reply, &err, 12);
				memcpy(reply+12, ofp_buffer, length);
				ofp_tx_write(self, reply, 12+length);
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


static uint16_t add_ofp13_flow(const struct ofp13_flow_mod *req){
	if(req->table_id > OFPP13_MAX){
		return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
	}
	if((req->flags & htons(OFPFF13_CHECK_OVERLAP)) != 0){
		int overlap = -1;
		for(int i=0; i<iLastFlow; i++){
			if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0
					|| req->table_id != fx_flows[i].table_id
					|| req->priority != fx_flows[i].priority){
				continue;
			}
			if(field_match13(req->match.oxm_fields, ntohs(req->match.length)-4,
					fx_flows[i].oxm, fx_flows[i].oxm_length) != 1){
				overlap = i;
				break;
			}
			if(field_match13(fx_flows[i].oxm, fx_flows[i].oxm_length,
					req->match.oxm_fields, ntohs(req->match.length)-4) != 1){
				overlap = i;
				break;
			}
		}
		if(overlap >= 0){
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_OVERLAP);
		}
	}

	struct ofp13_filter filter = {
		.strict = true,
		.table_id = req->table_id,
		.priority = ntohs(req->priority),
		.out_port = OFPP13_ANY,
		.out_group = OFPG13_ANY,
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.oxm_length = ntohs(req->match.length)-4,
		.oxm = req->match.oxm_fields,
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
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_TABLE_FULL);
		}else{
			n = iLastFlow++;
		}
	}
	uint16_t offset = offsetof(struct ofp13_flow_mod, match) + ALIGN8(ntohs(req->match.length));
	uint16_t oxm_len = ntohs(req->match.length) - 4;
	uint16_t ops_len = ntohs(req->header.length) - offset;
	const char *oxm = malloc(oxm_len);
	const char *ops = malloc(ops_len);
	if(oxm==NULL || ops==NULL){
		if(oxm!=NULL) free(oxm);
		if(ops!=NULL) free(ops);
		return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
	}
	
	fx_flows[n].send_bits = FX_FLOW_ACTIVE;
	fx_flows[n].table_id = req->table_id;
	fx_flows[n].priority = ntohs(req->priority);
	fx_flows[n].flags = ntohs(req->flags);
	if(fx_flows[n].oxm){
		free(fx_flows[n].oxm);
	}
	memcpy(oxm, req->match.oxm_fields, oxm_len);
	fx_flows[n].oxm = oxm;
	fx_flows[n].oxm_length = oxm_len;
	if(fx_flows[n].ops){
		free(fx_flows[n].ops);
	}
	memcpy(ops, (const char*)req + offset, ops_len);
	fx_flows[n].ops = ops;
	fx_flows[n].ops_length = ops_len;
	fx_flows[n].cookie = req->cookie;
	
	fx_flow_timeouts[n].hard_timeout = req->hard_timeout;
	fx_flow_timeouts[n].idle_timeout = req->idle_timeout;
	fx_flow_timeouts[n].init = sys_get_ms64();
	fx_flow_timeouts[n].update = sys_get_ms();
	
	if(found < 0 || (req->flags & htons(OFPFF13_RESET_COUNTS)) != 0){
		fx_flow_counts[n].byte_count = 0;
		fx_flow_counts[n].packet_count = 0;
	}
	if(ntohl(req->buffer_id) != OFP13_NO_BUFFER){
		// TODO: enqueue buffer
	}
	return 0;
}

static uint16_t modify_ofp13_flow(const struct ofp13_flow_mod *req, bool strict){
	if(req->table_id > OFPP13_MAX){
		return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_TABLE_ID);
	}

	struct ofp13_filter filter = {
		.strict = strict,
		.table_id = req->table_id,
		.priority = ntohs(req->priority),
		.out_port = OFPP13_ANY,
		.out_group = OFPG13_ANY,
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.oxm_length = ntohs(req->match.length)-4,
		.oxm = req->match.oxm_fields,
	};

	uint16_t inst_offset = offsetof(struct ofp13_flow_mod, match) + ALIGN8(ntohs(req->match.length));
	uint16_t inst_length = ntohs(req->header.length) - inst_offset;
	
	int count = 0;
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		count++;
	}
	const char **tmp = malloc(count*sizeof(const char*));
	for(int i=0; i<count; i++){
		tmp[i] = malloc(inst_length);
		if(tmp[i]==NULL){
			for(int j=0; j<i; j++){
				free(tmp[j]);
			}
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_UNKNOWN);
		}
	}
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		if(fx_flows[i].ops != NULL){
			free(fx_flows[i].ops);
		}
		char *ops = tmp[--count];
		memcpy(ops, (const char*)req + inst_offset, inst_length);
		fx_flows[i].ops = ops;
		fx_flows[i].ops_length = inst_length;
		
		if((req->flags & htons(OFPFF13_RESET_COUNTS)) != 0){
			fx_flow_counts[i].byte_count = 0;
			fx_flow_counts[i].packet_count = 0;
		}
	}
	free(tmp);
	if(req->buffer_id != htonl(OFP13_NO_BUFFER)){
		// TODO: enqueue buffer
	}
	return 0;
}

static uint16_t delete_ofp13_flow(const struct ofp13_flow_mod *req, bool strict){
	struct ofp13_filter filter = {
		.strict = strict,
		.table_id = req->table_id,
		.priority = ntohs(req->priority),
		.out_port = ntohl(req->out_port),
		.out_group = ntohl(req->out_group),
		.cookie = req->cookie,
		.cookie_mask = req->cookie_mask,
		.oxm_length = ntohs(req->match.length)-4,
		.oxm = req->match.oxm_fields,
	};
	for(int i=filter_ofp13_flow(0, filter); i>=0; i=filter_ofp13_flow(i+1, filter)){
		if(fx_flows[i].flags & OFPFF13_SEND_FLOW_REM != 0){
			uint8_t send_bits = 0;
			for(int i=0; i<MAX_CONTROLLERS; i++){
				send_bits |= 1<<i;
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
	return 0;
}

uint16_t mod_ofp13_flow(struct ofp13_flow_mod *req){
	switch(req->command){
		case OFPFC13_ADD:
			return add_ofp13_flow(req);
		
		case OFPFC13_MODIFY:
			return modify_ofp13_flow(req, false);
		
		case OFPFC13_MODIFY_STRICT:
			return modify_ofp13_flow(req, true);
		
		case OFPFC13_DELETE:
			return delete_ofp13_flow(req, false);
		
		case OFPFC13_DELETE_STRICT:
			return delete_ofp13_flow(req, true);
		
		default:
			return ofp_set_error(req, OFPET13_FLOW_MOD_FAILED, OFPFMFC13_BAD_COMMAND);
	}
}

static uint16_t add_ofp13_meter(const char* cmsg){
	struct ofp13_meter_mod req;
	memcpy(&req, cmsg, sizeof(struct ofp13_meter_mod));
	
	if(ntohl(req.meter_id)==OFPM13_ALL){
		return ofp_set_error(cmsg, OFPET13_METER_MOD_FAILED, OFPMMFC13_INVALID_METER);
	}
	// XXX: todo
	return ofp_set_error(cmsg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_METERS);
}

static uint16_t modify_ofp13_meter(const char* cmsg){
	struct ofp13_meter_mod req;
	memcpy(&req, cmsg, sizeof(struct ofp13_meter_mod));
	
	int count = 0;
	const char *pos = req.bands;
	while(pos < cmsg + htons(req.header.length)){
		struct ofp13_meter_band_header band;
		memcpy(&band, pos, sizeof(struct ofp13_meter_band_header));
		
		count++;
		pos += ntohs(band.len);
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
		return ofp_set_error(cmsg, OFPET13_METER_MOD_FAILED, OFPMMFC13_OUT_OF_BANDS);
	}
	// XXX: implement
	return 0;
}

static uint16_t delete_ofp13_meter(const char *cmsg){
	struct ofp13_meter_mod req;
	memcpy(&req, cmsg, sizeof(struct ofp13_meter_mod));
	
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
	return 0;
}

uint16_t mod_ofp13_meter(const char* cmsg){
	struct ofp13_meter_mod req;
	memcpy(&req, cmsg, sizeof(struct ofp13_meter_mod));
	
	uint32_t meter_id = ntohl(req.meter_id);
	// meter_id starts from 1
	if(meter_id==0 || (meter_id>OFPM13_MAX
			&& meter_id!=OFPM13_SLOWPATH && meter_id!=OFPM13_CONTROLLER
			&& meter_id!=OFPM13_ALL)){
		return ofp_set_error(cmsg, OFPET13_METER_MOD_FAILED, OFPMMFC13_INVALID_METER);
	}
	switch(ntohs(req.command)){
		case OFPMC13_ADD:
			return add_ofp13_meter(cmsg);
		case OFPMC13_MODIFY:
			return modify_ofp13_meter(cmsg);
		case OFPMC13_DELETE:
			return delete_ofp13_meter(cmsg);
		default:
			return ofp_set_error(cmsg, OFPET13_METER_MOD_FAILED, OFPFMFC13_BAD_COMMAND);
	}
}

uint16_t mod_ofp13_group(const char *cmsg){
	struct ofp13_group_mod req;
	memcpy(&req, cmsg, sizeof(struct ofp13_group_mod));
	
	uint32_t group_id = ntohl(req.group_id);
	if(group_id > OFPG13_MAX){
		
	}
	// TODO: implement this
	return 0;
}

static int bits_on(const char *data, int len){
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

int match_frame_by_oxm(struct fx_packet *packet, struct fx_packet_oob *oob, const char *oxm, uint16_t oxm_length){
	int count = 0;
	for(const char *pos=oxm; pos<oxm+oxm_length; pos+=4+(uint8_t)oxm[3]){
		if((uint8_t)pos[0]==0x80 && (uint8_t)pos[1]==0x00){
			int has_mask = (uint8_t)pos[2] & 0x01;
			switch((uint8_t)pos[2]>>1){
				case OFPXMT13_OFB_IN_PORT:
				if(memcmp(&packet->in_port, pos+4, 4)!=0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_IN_PHY_PORT:
				if(memcmp(&packet->in_phy_port, pos+4, 4) != 0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_METADATA:
				{
					uint64_t value;
					if(has_mask){
						memcpy(&value, pos+12, 8);
						value &= packet->metadata;
						count += bits_on(pos+12, 8);
					} else {
						value = packet->metadata;
						count += 64;
					}
					if(memcmp(&value, pos+4, 8)!=0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_DST:
				{
					char mac[6];
					pbuf_copy_partial(packet->data, mac, 6, 0);
					if(has_mask){
						for(int i=0; i<6; i++){
							mac[i] &= pos[10+i];
						}
						count += bits_on(pos+10, 6);
					}else{
						count += 48;
					}
					if(memcmp(mac, pos+4, 6) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_SRC:
				{
					char mac[6];
					pbuf_copy_partial(packet->data, mac, 6, 6);
					if(has_mask){
						for(int i=0; i<6; i++){
							mac[i] &= pos[10+i];
						}
						count += bits_on(pos+10, 6);
					} else {
						count += 48;
					}
					if(memcmp(mac, pos+4, 6) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_ETH_TYPE:
				if(memcmp(oob->eth_type, pos+4, 2) != 0){
					return -1;
				}
				break;
				
				case OFPXMT13_OFB_VLAN_VID:
				{
					uint16_t vlan;
					if(has_mask){
						memcpy(&vlan, pos+6, 2);
						vlan &= oob->vlan & htons(0x1FFF);
						count += bits_on(pos+6, 2);
					} else {
						vlan = oob->vlan & htons(0x1FFF);
						count += 16;
					}
					if(memcmp(&vlan, pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_VLAN_PCP:
				{
					if((oob->vlan & htons(0x1000)) == 0){
						return -1;
					}
					uint8_t pcp;
					pcp = ntohs(oob->vlan)>>13;
					if(has_mask){
						pcp &= pos[5];
						count += bits_on(pos+5, 1);
					} else {
						count += 8;
					}
					if(pcp != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IP_DSCP:
				{
					uint8_t dscp;
					if(oob->eth_type == htons(0x0800)){
						struct ip_hdr *hdr = packet->data->payload + oob->eth_offset;
						dscp = IPH_TOS(hdr)>>2;
					} else if(oob->eth_type == htons(0x86dd)){
						return -1; // TODO
					} else {
						return -1;
					}
					if(dscp != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IP_ECN:
				{
					uint8_t ecn;
					if(oob->eth_type == htons(0x0800)){
						struct ip_hdr *hdr = packet->data->payload + oob->eth_offset;
						ecn = IPH_TOS(hdr)&0x03;
					} else if(oob->eth_type == htons(0x86dd)){
						return -1; // TODO
					} else {
						return -1;
					}
					if(ecn != pos[4]){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IPV4_SRC:
				if(oob->eth_type == htons(0x0800)){
					struct ip_hdr *hdr = packet->data->payload + oob->eth_offset;
					uint32_t value;
					if(has_mask){
						memcpy(&value, pos+8, 4);
						value &= hdr->src.addr;
						count += bits_on(pos+8, 4);
					} else {
						value = hdr->src.addr;
						count += 32;
					}
					if(memcmp(&value, pos+4, 4)!=0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_IPV4_DST:
				if(oob->eth_type == htons(0x0800)){
					struct ip_hdr *hdr = packet->data->payload + oob->eth_offset;
					uint32_t value;
					if(has_mask){
						memcpy(&value, pos+8, 4);
						value &= hdr->dest.addr;
						count += bits_on(pos+8, 4);
					} else {
						value = hdr->dest.addr;
						count += 32;
					}
					if(memcmp(&value, pos+4, 4)!=0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_TCP_SRC:
				{
					if(oob->eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet->data->payload + oob->eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *tcphdr = (struct tcp_hdr *)(packet->data->payload
						+ oob->eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(tcphdr->src), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_TCP_DST:
				{
					if(oob->eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet->data->payload + oob->eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct tcp_hdr *tcphdr = (struct tcp_hdr *)(packet->data->payload
						+ oob->eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(tcphdr->dest), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_UDP_SRC:
				{
					if(oob->eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet->data->payload + oob->eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct udp_hdr *udphdr = (struct udp_hdr *)(packet->data->payload
						+ oob->eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(udphdr->src), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
				
				case OFPXMT13_OFB_UDP_DST:
				{
					if(oob->eth_type != htons(0x0800)){
						return -1;
					}
					struct ip_hdr *iphdr = (struct ip_hdr *)(packet->data->payload + oob->eth_offset);
					if(IPH_PROTO(iphdr)!=6){
						return -1;
					}
					struct udp_hdr *udphdr = (struct udp_hdr *)(packet->data->payload
						+ oob->eth_offset + IPH_HL(iphdr) * 4);
					if(memcmp(&(udphdr->dest), pos+4, 2) != 0){
						return -1;
					}
				}
				break;
			}
		}
	}
	return count;
}

static void send_ofp13_packet_in(struct fx_packet *packet, struct ofp13_packet_in base, uint16_t max_len, uint8_t *send_bits){
	if(max_len == OFPCML13_NO_BUFFER || max_len > packet->data->tot_len){
		max_len = packet->data->tot_len;
	} // max_len is send_len
	
	base.header.type = OFPT13_PACKET_IN;
	base.header.version = 4;
	base.total_len = packet->data->tot_len;
	
	char oxm[32];
	uint16_t oxm_length = 0;
	if(packet->in_port != 0){
		uint32_t field = htonl(OXM_OF_IN_PORT);
		memcpy(oxm+oxm_length, &field, 4);
		memcpy(oxm+oxm_length+4, &packet->in_port, 4);
		oxm_length += 8;
	}
	if(packet->metadata != 0){
		uint32_t field = htonl(OXM_OF_METADATA);
		memcpy(oxm+oxm_length, &field, 4);
		memcpy(oxm+oxm_length+4, &packet->metadata, 8);
		oxm_length += 12;
	}
	if(packet->tunnel_id != 0){
		uint32_t field = htonl(OXM_OF_TUNNEL_ID);
		memcpy(oxm+oxm_length, &field, 4);
		memcpy(oxm+oxm_length+4, &packet->tunnel_id, 8);
		oxm_length += 12;
	}
	base.match.type = htons(OFPMT13_OXM);
	base.match.length = htons(4 + oxm_length);
	
	uint16_t length = offsetof(struct ofp13_packet_in, match);
	length += ALIGN8(4+oxm_length) + 2 + max_len;
	base.header.length = htons(length);
	
	memset(ofp_buffer, 0, length);
	memcpy(ofp_buffer, &base, sizeof(struct ofp13_packet_in));
	memcpy(ofp_buffer+offsetof(struct ofp13_packet_in, match)+4, oxm, oxm_length);
	pbuf_copy_partial(packet->data,
		ofp_buffer+offsetof(struct ofp13_packet_in, match)+ALIGN8(4+oxm_length)+2,
		max_len, 0);
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
		uint32_t xid = ofp->xid++;
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
			pbuf_free(pin->packet.data);
			pin->send_bits = 0;
			continue;
		}
		struct ofp13_packet_in msg = {};
		msg.buffer_id = pin->buffer_id;
		msg.reason = pin->reason;
		msg.table_id = pin->table_id;
		msg.cookie = pin->cookie;
		send_ofp13_packet_in(&pin->packet, msg, ntohs(pin->max_len), &pin->send_bits);
		if(pin->send_bits == 0){
			pbuf_free(pin->packet.data);
		}
	}
}

static void execute_ofp13_action(struct fx_packet *packet, struct fx_packet_oob *oob, struct ofp13_action_header *act, int flow){
	switch(ntohs(act->type)){
		case OFPAT13_OUTPUT:
		{
			struct ofp13_action_output *out = act;
			uint32_t port = ntohl(out->port) - 1; // port starts from 1
			if(port < OFPP13_MAX){
				if(out->port != packet->in_port && port<4 && Zodiac_Config.of_port[port]==1){
					if(disable_ofp_pipeline == false){
						fx_port_counts[port].tx_packets++;
						pbuf_copy_partial(packet->data, ofp_buffer, packet->data->tot_len, 0);
						gmac_write(ofp_buffer, packet->data->tot_len, 1<<port);
					}
				}
			}else if(out->port == htonl(OFPP13_ALL) || out->port == htonl(OFPP13_FLOOD) || out->port == htonl(OFPP13_NORMAL)){
				if(disable_ofp_pipeline == false){
					uint8_t p = 0;
					for(int i=0; i<4; i++){ // XXX: num port hardcoded
						if(Zodiac_Config.of_port[i]==1 && i != ntohl(packet->in_port)-1){
							p |= 1<<i;
							fx_port_counts[i].tx_packets++;
						}
					}
					if(p != 0){
						pbuf_copy_partial(packet->data, ofp_buffer, packet->data->tot_len, 0);
						gmac_write(ofp_buffer, packet->data->tot_len, p);
					}
				}
			}else if(out->port == htonl(OFPP13_CONTROLLER)){
				struct ofp13_packet_in msg = {};
				uint8_t send_bits = 0;
				msg.buffer_id = htonl(OFP13_NO_BUFFER);
				if(out->max_len != htons(OFPCML13_NO_BUFFER)){
					send_bits |= 0x80;
					msg.buffer_id = htonl(fx_buffer_id++);
				}
				msg.reason = OFPR13_ACTION;
				if(flow < 0){
					msg.table_id = 0;
					memset(&msg.cookie, 0xff, 8); // openvswitch does this
				} else {
					msg.table_id = fx_flows[flow].table_id;
					msg.cookie = fx_flows[flow].cookie;
					if(fx_flows[flow].priority == 0 && fx_flows[flow].oxm_length == 0){
						// table-miss
						msg.reason = OFPR13_NO_MATCH;
					}
				}
				
				for(int i=0; i<MAX_CONTROLLERS; i++){
					if(controllers[i].ofp.negotiated){
						send_bits |= 1<<i;
					}
				}
				send_ofp13_packet_in(packet, msg, ntohs(out->max_len), &send_bits);
				if(send_bits != 0){
					for(int i=0; i<MAX_BUFFERS; i++){
						struct fx_packet_in *pin = fx_packet_ins+i;
						if(pin->send_bits == 0){
							pin->send_bits = send_bits;
							pin->valid_until = sys_get_ms() + BUFFER_TIMEOUT;
							
							pin->buffer_id = msg.buffer_id;
							pin->reason = msg.reason;
							pin->table_id = msg.table_id;
							pin->cookie = msg.cookie;
							
							struct pbuf *data = pbuf_alloc(PBUF_RAW, packet->data->tot_len, PBUF_POOL);
							pbuf_copy(data, packet->data);
							pin->packet = *packet;
							pin->packet.data = data;
							pin->max_len = out->max_len;
							break;
						}
					}
				}
			}
		}
		break;
		
		case OFPAT13_COPY_TTL_OUT:
		if(oob->eth_type==htons(0x8848) || oob->eth_type==htons(0x8848)){
			// MPLS header structure
			// check bottom
		}
		break;
		
		case OFPAT13_PUSH_VLAN:
		{
			struct ofp13_action_push *ap = act;
			uint16_t vlan = oob->vlan & htons(0xEFFF); // clear CFI
			// pbuf can't grow as of lwip 1.4
			struct pbuf *grow = pbuf_alloc(PBUF_RAW,
				packet->data->tot_len + 4, PBUF_POOL);
			pbuf_copy_partial(packet->data, grow->payload, 12, 0);
			memcpy(grow->payload+12, &ap->ethertype, 2);
			memcpy(grow->payload+14, &vlan, 2);
			pbuf_copy_partial(packet->data, grow->payload+16, packet->data->tot_len - 12, 12);
			pbuf_free(packet->data);
			packet->data = grow;
			create_oob(packet->data, oob);
		}
		break;
		
		case OFPAT13_POP_VLAN:
		if(oob->vlan & htons(0x1000) != 0){
			struct pbuf *data = packet->data;
			memmove(data->payload+12, data->payload+16, data->tot_len - 16);
			pbuf_realloc(data, data->tot_len-16);
			create_oob(packet->data, oob);
		}
		break;
		
		case OFPAT13_SET_NW_TTL:
		if(oob->eth_type == htons(0x0806)){
			struct ofp13_action_nw_ttl *an = act;
			struct ip_hdr *hdr = packet->data->payload + oob->eth_offset;
			IPH_TTL_SET(hdr, an->nw_ttl);
		} // TODO: IPv6, MPLS
		break;
		
		case OFPAT13_DEC_NW_TTL:
		if(oob->eth_type == htons(0x0806)){
			struct ofp13_action_nw_ttl *an = act;
			struct ip_hdr *hdr = packet->data->payload + oob->eth_offset;
			uint8_t ttl = IPH_TTL(hdr);
			if(ttl == 1){
				struct ofp13_packet_in msg = {};
				uint8_t send_bits = 0;
				msg.buffer_id = htonl(OFP13_NO_BUFFER);
				if(fx_switch.miss_send_len != htons(OFPCML13_NO_BUFFER)){
					send_bits |= 0x80;
					msg.buffer_id = htonl(fx_buffer_id++);
				}
				msg.reason = OFPR13_INVALID_TTL;
				if(flow < 0){
					msg.table_id = 0;
					memset(&msg.cookie, 0xff, 8); // openvswitch does this
				} else {
					msg.table_id = fx_flows[flow].table_id;
					msg.cookie = fx_flows[flow].cookie;
				}
				
				for(int i=0; i<MAX_CONTROLLERS; i++){
					if(controllers[i].ofp.negotiated){
						send_bits |= 1<<i;
					}
				}
				send_ofp13_packet_in(packet, msg, ntohs(fx_switch.miss_send_len), &send_bits);
				if(send_bits != 0){
					for(int i=0; i<MAX_BUFFERS; i++){
						struct fx_packet_in *pin = fx_packet_ins+i;
						if(pin->send_bits == 0){
							pin->send_bits = send_bits;
							pin->valid_until = sys_get_ms() + BUFFER_TIMEOUT;
							
							pin->buffer_id = msg.buffer_id;
							pin->reason = msg.reason;
							pin->table_id = msg.table_id;
							pin->cookie = msg.cookie;
							
							struct pbuf *data = pbuf_alloc(PBUF_RAW, packet->data->tot_len, PBUF_POOL);
							pbuf_copy(data, packet->data);
							pin->packet = *packet;
							pin->packet.data = data;
							pin->max_len = fx_switch.miss_send_len;
							break;
						}
					}
				}
			} else {
				IPH_TTL_SET(hdr, ttl-1);
			}
		} // TODO: IPv6, MPLS
		break;
	}
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
	const char* insts[8] = {};
	const char *pos = fx_flows[flow].ops;
	while(pos < fx_flows[flow].ops+fx_flows[flow].ops_length){
		struct ofp13_instruction hdr;
		memcpy(&hdr, pos, sizeof(struct ofp13_instruction));
		uint16_t itype = ntohs(hdr.type);
		if(itype < 8){
			insts[itype] = pos;
		}
		pos += ntohs(hdr.len);
	}
	
	pos = insts[OFPIT13_METER];
	if(pos != NULL){
		// todo
	}
	pos = insts[OFPIT13_APPLY_ACTIONS];
	if(pos != NULL){
		struct ofp13_instruction_actions *ia = pos;
		const char *p = ia->actions;
		while(p < pos+ntohs(ia->len)){
			struct ofp13_action_header *act = p;
			execute_ofp13_action(packet, oob, act, flow);
			p += ntohs(act->len);
		}
	}
	pos = insts[OFPIT13_CLEAR_ACTIONS];
	if(pos != NULL){
		memset(oob->action_set, 0, sizeof(const char*)*16);
		if(oob->action_set_oxm != NULL){
			free(oob->action_set_oxm);
			oob->action_set_oxm = NULL;
		}
		oob->action_set_oxm_length = 0;
	}
	pos = insts[OFPIT13_WRITE_ACTIONS];
	if(pos != NULL){
		struct ofp13_instruction_actions *ia = pos;
		const char *p = ia->actions;
		while(p < pos+ntohs(ia->len)){
			struct ofp13_action_header *act = p;
			for(int i=0; i<sizeof(actset_index)/sizeof(uint16_t); i++){
				if(actset_index[i] == ntohs(act->type)){
					oob->action_set[i] = p;
				}
			}
			p += ntohs(act->len);
		}
	}
	pos = insts[OFPIT13_WRITE_METADATA];
	if(pos != NULL){
		struct ofp13_instruction_write_metadata *iw = pos;
		packet->metadata &= ~iw->metadata_mask;
		packet->metadata |= (iw->metadata & iw->metadata_mask);
	}
	pos = insts[OFPIT13_GOTO_TABLE];
	if(pos != NULL){
		struct ofp13_instruction_goto_table *ig = pos;
		uint8_t table = ig->table_id;
		if(table < MAX_TABLES){
			flow = lookup_fx_table(packet, oob, table);
			fx_table_counts[table].lookup++;
			if(flow < 0){
				return;
			}
			fx_table_counts[table].matched++;
			fx_flow_counts[flow].packet_count++;
			fx_flow_counts[flow].byte_count+=packet->data->tot_len;
			fx_flow_timeouts[flow].update = sys_get_ms();
			execute_fx_flow(packet, oob, flow);
		}
		return;
	}
	// execute action set
	for(int i=0; i<sizeof(actset_index)/sizeof(uint16_t); i++){
		if(oob->action_set[i] == NULL){
			continue;
		}
		execute_ofp13_action(packet, oob, oob->action_set[i], flow);
	}
}

enum ofp_pcb_status ofp13_handle(struct ofp_pcb *self){
	if(ofp_rx_length(self) < 8){
		return OFP_NOOP;
	};
	struct ofp_header req; // look ahead
	pbuf_copy_partial(self->rbuf, &req, 8, self->rskip);
	uint16_t length = ntohs(req.length);
	switch(req.type){
		case OFPT13_FEATURES_REQUEST:
		if(ofp_tx_room(self) < 32){
			return OFP_NOOP;
		} else {
			ofp_rx_read(self, ofp_buffer, length);
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
			char dpid[8] = {};
			memcpy(dpid+2, Zodiac_Config.MAC_address, 6);
			memcpy(&res.datapath_id, dpid, 8);
			return ofp_tx_write(self, &res, 32);
		}
		break;

		case OFPT13_GET_CONFIG_REQUEST:
		if(ofp_tx_room(self) < 12){
			return OFP_NOOP;
		}else{
			ofp_rx_read(self, ofp_buffer, length);
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
			return ofp_tx_write(self, &res, 12);
		}
		break;

		case OFPT13_SET_CONFIG:
		if(ofp_rx_length(self) < 12 || ofp_tx_room(self) < 12+64){
			return OFP_NOOP;
		} else {
			struct ofp13_switch_config req;
			ofp_rx_read(self, &req, 12);
			ofp_rx_read(self, ofp_buffer, length-12); //safety
			fx_switch.flags = ntohs(req.flags); // XXX: add tcp_reass() support
			fx_switch.miss_send_len = ntohs(req.miss_send_len);
			// XXX: ofp_error may be raised
		}
		break;

		case OFPT13_PACKET_OUT:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			return OFP_NOOP;
		}else{
			ofp_rx_read(self, ofp_buffer, length);
			struct ofp13_packet_out *hint = ofp_buffer;
			
			struct fx_packet packet = {
				.in_port = hint->in_port,
			};
			if(hint->buffer_id != htonl(OFP13_NO_BUFFER)){
				bool found = false;
				for(int i=0; i<MAX_BUFFERS; i++){
					if((fx_packet_ins[i].send_bits & 0x80) == 0){
						continue;
					}
					if(fx_packet_ins[i].buffer_id != hint->buffer_id){
						continue;
					}
					packet.data = fx_packet_ins[i].packet.data, // ownership moves
					fx_packet_ins[i].send_bits = 0;
					found = true;
					memset(fx_packet_ins+i, 0, sizeof(struct fx_packet_in));
					break;
				}
				if(found == false){
					uint16_t len = ofp_set_error(ofp_buffer, OFPET13_BAD_REQUEST, OFPBRC13_BUFFER_UNKNOWN);
					return ofp_tx_write(self, ofp_buffer, len);
				}
			}else{
				uint16_t len = offsetof(struct ofp13_packet_out, actions);
				len += ntohs(hint->actions_len);
				struct pbuf *data = pbuf_alloc(PBUF_RAW, length-len, PBUF_POOL);
				memcpy(data->payload, hint+length-len, length-len);
				packet.data = data;
			}
			struct fx_packet_oob oob;
			create_oob(packet.data, &oob);
			
			const char *p = hint->actions;
			while(p < hint->actions+ntohs(hint->actions_len)){
				struct ofp13_action_header *act = p;
				execute_ofp13_action(&packet, &oob, act, -1);
				p += ntohs(act->len);
			}
			pbuf_free(packet.data); // free that obtained pbuf
					
		}
		break;

		case OFPT13_FLOW_MOD:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			return OFP_NOOP;
		} else {
			ofp_rx_read(self, ofp_buffer, length);
			uint16_t len = mod_ofp13_flow((struct ofp13_flow_mod*)ofp_buffer);
			if(len > 0){
				return ofp_tx_write(self, ofp_buffer, len);
			}
		}
		break;

		case OFPT13_GROUP_MOD:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			return OFP_NOOP;
		} else {
			ofp_rx_read(self, ofp_buffer, length);
			uint16_t len = mod_ofp13_group((struct ofp13_group_mod*)ofp_buffer);
			if(len > 0){
				return ofp_tx_write(self, ofp_buffer, len);
			}
		}
		break;

		case OFPT13_METER_MOD:
		if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
			return OFP_NOOP;
		} else {
			ofp_rx_read(self, ofp_buffer, length);
			uint16_t len = mod_ofp13_meter((struct ofp13_meter_mod*)ofp_buffer);
			if(len > 0){
				return ofp_tx_write(self, ofp_buffer, len);
			}
		}
		break;

		default:
			if(ofp_rx_length(self) < length || ofp_tx_room(self) < 12+64){
				return OFP_NOOP;
			} else {
				ofp_rx_read(self, ofp_buffer, length);
			}
			ofp_set_error(ofp_buffer, OFPET13_BAD_REQUEST, OFPBRC13_BAD_TYPE);
			ofp_tx_write(self, ofp_buffer, 12+length);
			return OFP_OK;
		break;
	}
	return OFP_OK;
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
				if(fx_flows[i].flags & OFPFF13_SEND_FLOW_REM != 0 ){
					fx_flows[i].send_bits = send_bits;
				} else {
					fx_flows[i].send_bits = 0;
				}
			}
		}
		if(fx_flow_timeouts[i].idle_timeout != 0){
			uint32_t timeout = fx_flow_timeouts[i].update + fx_flow_timeouts[i].idle_timeout;
			if(timeout - sys_get_ms() > 0x80000000){
				if(fx_flows[i].flags & OFPFF13_SEND_FLOW_REM != 0 ){
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
			if(fx_ports[j].send_bits & bits != 0){
				if(Zodiac_Config.of_port[j] == 1){
					reason = OFPPR13_ADD;
				}else{
					reason = OFPPR13_DELETE;
				}
			}else if(fx_ports[j].send_bits_mod & bits != 0){
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

