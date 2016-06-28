/**
 * @file
 * of_helper.c
 *
 * This file contains the main OpenFlow helper functions
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
#include "config_zodiac.h"
#include "openflow.h"
#include "of_helper.h"
#include "lwip/tcp.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "switch.h"

#define ALIGN8(x) (x+7)/8*8

// Global variables
extern int iLastFlow;
extern int OF_Version;

uint32_t packet_hash(const void *data, uint16_t length){
	uint32_t L[12] = {0};
	if(length > 48){ length=48; }
	memcpy(L, data, length);
	return L[0]^L[1]^L[2]^L[3]^L[4]^L[5]^L[6]^L[7]^L[8]^L[9]^L[10]^L[11];
}


void set_csum_tp_zero(void *data, uint16_t length, uint16_t iphdr_offset){
	struct ip_hdr *iphdr = (void*)((uintptr_t)data + iphdr_offset);
	struct ip4_addr src = {
		.addr = iphdr->src.addr,
	};
	struct ip4_addr dst = {
		.addr = iphdr->dest.addr,
	};
	uint16_t payload_offset = iphdr_offset + IPH_HL(iphdr)*4;
	if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
		struct tcp_hdr *tcphdr = (void*)((uintptr_t)data + payload_offset);
		tcphdr->chksum = 0;
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		struct udp_hdr *udphdr = (void*)((uintptr_t)data + payload_offset);
		udphdr->chksum = 0;
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
		struct icmp_echo_hdr *icmphdr = (void*)((uintptr_t)data + payload_offset);
		icmphdr->chksum = 0;
	}
	IPH_CHKSUM_SET(iphdr, 0);
}

/*
*	Updates the IP Checksum after a SET FIELD operation.
*	Returns the flow number if it matches.
*
*	@param *p_uc_data - Pointer to the buffer that contains the packet to be updated.
*	@param packet_size - The size of the packet.
*	@param iphdr_offset - IP Header offset.
*	
*/
void set_ip_checksum(void *p_uc_data, uint16_t packet_size, uint16_t iphdr_offset)
{
	struct ip_hdr *iphdr = (void*)((uintptr_t)p_uc_data + iphdr_offset);
	struct ip4_addr src = {
		.addr = iphdr->src.addr,
	};
	struct ip4_addr dst = {
		.addr = iphdr->dest.addr,
	};
	uint16_t payload_offset = iphdr_offset + IPH_HL(iphdr)*4;
	uint16_t payload_length = ntohs(IPH_LEN(iphdr)) - IPH_HL(iphdr)*4;
	if(payload_offset + payload_length > packet_size){
		return; // safety
	}
	struct pbuf *p = pbuf_alloc(PBUF_RAW, payload_length, PBUF_REF);
	p->payload = (void*)((uintptr_t)p_uc_data + payload_offset);
	if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
		struct tcp_hdr *tcphdr = (void*)((uintptr_t)p_uc_data + payload_offset);
		tcphdr->chksum = 0;
		tcphdr->chksum = inet_chksum_pseudo(p, IP_PROTO_TCP, payload_length, &src, &dst);
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		struct udp_hdr *udphdr = (void*)((uintptr_t)p_uc_data + payload_offset);
		udphdr->chksum = 0;
		udphdr->chksum = inet_chksum_pseudo(p, IP_PROTO_UDP, payload_length, &src, &dst);
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
		struct icmp_echo_hdr *icmphdr = (void*)((uintptr_t)p_uc_data + payload_offset);
		icmphdr->chksum = 0;
		icmphdr->chksum = inet_chksum(icmphdr, payload_length);
	}
	pbuf_free(p);
	
	IPH_CHKSUM_SET(iphdr, 0);
	IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IPH_HL(iphdr)*4));
}

/*
*	Updates the IPv6 Checksum after a SET FIELD operation.
*	Returns the flow number if it matches.
*
*	@param *p_uc_data - Pointer to the buffer that contains the packet to be updated.
*	@param packet_size - The size of the packet.
*	@param iphdr_offset - IP Header offset.
*	
*/
void set_ip6_checksum(void *p_uc_data, uint16_t packet_size, struct fx_packet_oob *oob)
{
	struct ip6_hdr *iphdr = (void*)((uintptr_t)p_uc_data + oob->eth_type_offset + 2);
	struct ip6_addr src = {
		.addr = {
			iphdr->src.addr[0],
			iphdr->src.addr[1],
			iphdr->src.addr[2],
			iphdr->src.addr[3],
		}
	};
	struct ip6_addr dst = {
		.addr = {
			iphdr->dest.addr[0],
			iphdr->dest.addr[1],
			iphdr->dest.addr[2],
			iphdr->dest.addr[3],
		}
	};
	struct pbuf *p = pbuf_alloc(PBUF_RAW, packet_size - oob->ipv6_tp_offset, PBUF_REF);
	p->payload = (void*)((uintptr_t)p_uc_data + oob->ipv6_tp_offset);
	if (oob->ipv6_tp_type == IP6_NEXTH_TCP) {
		struct tcp_hdr *tcphdr = (void*)((uintptr_t)p_uc_data + oob->ipv6_tp_offset);
		tcphdr->chksum = 0;
		tcphdr->chksum = ip6_chksum_pseudo(p, IP6_NEXTH_TCP, packet_size - oob->ipv6_tp_offset, &src, &dst);
	}
	if (oob->ipv6_tp_type == IP6_NEXTH_UDP) {
		struct udp_hdr *udphdr = (void*)((uintptr_t)p_uc_data + oob->ipv6_tp_offset);
		udphdr->chksum = 0;
		udphdr->chksum = ip6_chksum_pseudo(p, IP6_NEXTH_UDP, packet_size - oob->ipv6_tp_offset, &src, &dst);
	}
	if (oob->ipv6_tp_type == IP6_NEXTH_ICMP6) {
		uint8_t *hdr = p_uc_data + oob->ipv6_tp_offset;
		hdr[2] = hdr[3] = 0;
		uint16_t csum = ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, packet_size - oob->ipv6_tp_offset, &src, &dst);
		memcpy(hdr+2, &csum, 2);
	}
	pbuf_free(p);
}

#define PREREQ_INVALID 1<<0
#define PREREQ_VLAN 1<<1
#define PREREQ_IPV4 1<<2
#define PREREQ_IPV6 1<<3
#define PREREQ_ARP 1<<4
#define PREREQ_TCP 1<<5
#define PREREQ_UDP 1<<6
#define PREREQ_SCTP 1<<7
#define PREREQ_ICMPV4 1<<8
#define PREREQ_ICMPV6 1<<9
#define PREREQ_ND_SLL 1<<10
#define PREREQ_ND_TLL 1<<11
#define PREREQ_MPLS 1<<12
#define PREREQ_PBB 1<<13
#define PREREQ_ETH_TYPE_MASK (PREREQ_IPV4 | PREREQ_IPV6 | PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)
#define PREREQ_IP_PROTO_MASK (PREREQ_TCP | PREREQ_UDP | PREREQ_SCTP | PREREQ_ICMPV4 | PREREQ_ICMPV6)
#define PREREQ_IP_MASK (PREREQ_IPV4 | PREREQ_IPV6)
#define PREREQ_ND_MASK (PREREQ_ND_SLL | PREREQ_ND_TLL)

static uint32_t match_prereq(const void *oxms, int length)
{
	uint32_t ret = 0;
	uintptr_t hdr = (uintptr_t)oxms;
	while(hdr < (uintptr_t)oxms+length){
		const uint8_t *oxm = (const uint8_t*)hdr;
		const uint32_t field = ntohl(*(const uint32_t*)hdr);
		switch(field){
			case OXM_OF_VLAN_PCP:
				ret |= PREREQ_VLAN;
				break;
			case OXM_OF_ETH_TYPE:
				switch(ntohs(*(uint16_t*)(hdr+4))){
					case 0x0800:
						if ((ret & PREREQ_IP_MASK) == PREREQ_IPV6){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV4;
						break;
					case 0x86dd:
						if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
						break;
					case 0x0806:
						ret |= PREREQ_ARP;
						break;
					case 0x8847:
					case 0x8848:
						ret |= PREREQ_MPLS;
						break;
					case 0x88e7:
						ret |= PREREQ_PBB;
						break;
				}
				break;
			case OXM_OF_IP_PROTO:
				switch(oxm[4]){
					case 1:
						ret |= PREREQ_ICMPV4;
						break;
					case 6:
						ret |= PREREQ_TCP;
						break;
					case 17:
						ret |= PREREQ_UDP;
						break;
					case 58:
						ret |= PREREQ_ICMPV6;
						break;
					case 132:
						ret |= PREREQ_SCTP;
						break;
				}
				if ((ret & PREREQ_IP_MASK) == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_ICMPV6_TYPE:
				switch(oxm[4]){
					case 135:
						if ((ret & PREREQ_ND_MASK) == PREREQ_ND_TLL){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_SLL;
						break;
					case 136:
						if ((ret & PREREQ_ND_MASK) == PREREQ_ND_SLL){
							ret |= PREREQ_INVALID;
						}
						ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_TLL;
						break;
				}
				ret |= PREREQ_ICMPV6;
				if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IP_DSCP:
			case OXM_OF_IP_ECN:
				if ((ret & PREREQ_IP_MASK) == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_ICMPV4_TYPE:
			case OXM_OF_ICMPV4_CODE:
				ret |= PREREQ_ICMPV4;
			case OXM_OF_IPV4_DST:
			case OXM_OF_IPV4_DST_W:
			case OXM_OF_IPV4_SRC:
			case OXM_OF_IPV4_SRC_W:
				if ((ret & PREREQ_IP_MASK) == PREREQ_IPV6){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV4;
				break;
			case OXM_OF_TCP_SRC:
			case OXM_OF_TCP_DST:
				ret |= PREREQ_TCP;
				if ((ret & PREREQ_IP_MASK) == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_UDP_SRC:
			case OXM_OF_UDP_DST:
				ret |= PREREQ_UDP;
				if ((ret & PREREQ_IP_MASK) == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_SCTP_SRC:
			case OXM_OF_SCTP_DST:
				ret |= PREREQ_SCTP;
				if ((ret & PREREQ_IP_MASK) == 0 ){
					ret |= PREREQ_IP_MASK;
				}
				break;
			case OXM_OF_ARP_OP:
			case OXM_OF_ARP_SPA:
			case OXM_OF_ARP_SPA_W:
			case OXM_OF_ARP_TPA:
			case OXM_OF_ARP_TPA_W:
			case OXM_OF_ARP_SHA:
			case OXM_OF_ARP_THA:
				ret |= PREREQ_ARP;
				break;
			case OXM_OF_ICMPV6_CODE:
				ret |= PREREQ_ICMPV6;
			case OXM_OF_IPV6_SRC:
			case OXM_OF_IPV6_SRC_W:
			case OXM_OF_IPV6_DST:
			case OXM_OF_IPV6_DST_W:
			case OXM_OF_IPV6_FLABEL:
			case OXM_OF_IPV6_EXTHDR:
			case OXM_OF_IPV6_EXTHDR_W:
				if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IPV6_ND_TARGET:
				if ((ret & PREREQ_ND_MASK) == 0){
					ret |= PREREQ_ND_MASK;
				}
				ret |= PREREQ_ICMPV6;
				if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IPV6_ND_SLL:
				if ((ret & PREREQ_ND_MASK) == PREREQ_ND_TLL){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_SLL;
				ret |= PREREQ_ICMPV6;
				if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_IPV6_ND_TLL:
				if ((ret & PREREQ_ND_MASK) == PREREQ_ND_SLL){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_ND_MASK) | PREREQ_ND_TLL;
				ret |= PREREQ_ICMPV6;
				if ((ret & PREREQ_IP_MASK) == PREREQ_IPV4){
					ret |= PREREQ_INVALID;
				}
				ret = (ret & ~PREREQ_IP_MASK) | PREREQ_IPV6;
				break;
			case OXM_OF_MPLS_LABEL:
			case OXM_OF_MPLS_BOS:
			case OXM_OF_MPLS_TC:
				ret |= PREREQ_MPLS;
				break;
			case OXM_OF_PBB_ISID:
				ret |= PREREQ_PBB;
				break;
		}
		hdr += 4 + OXM_LENGTH(field);
	}
	uint32_t flags = 0;
	flags = ret & PREREQ_ETH_TYPE_MASK;
	if (flags!=0 && flags!=PREREQ_IPV4 && flags!=PREREQ_IPV6 && flags!=PREREQ_IP_MASK && flags!=PREREQ_ARP && flags!=PREREQ_MPLS && flags!=PREREQ_PBB){
		ret |= PREREQ_INVALID;
	}
	flags = ret & PREREQ_IP_PROTO_MASK;
	if (flags!=0 && flags!=PREREQ_TCP && flags!=PREREQ_UDP && flags!=PREREQ_SCTP && flags!=PREREQ_ICMPV4 && flags!=PREREQ_ICMPV6){
		ret |= PREREQ_INVALID;
	}
	return ret;
}

/*
 *	compares two oxm sequence.
 */
bool oxm_strict_equals(const void *oxm_a, int len_a, const void *oxm_b, int len_b){
	int count_a = 0;
	for(const uint8_t *pos_a=oxm_a; pos_a < (const uint8_t*)oxm_a+len_a; pos_a += 4+pos_a[3]){
		bool miss = true;
		for(const uint8_t *pos_b=oxm_b; pos_b < (const uint8_t*)oxm_b+len_b; pos_b += 4+pos_b[3]){
			if(pos_a[3] == pos_b[3] && memcmp(pos_a+4, pos_b+4, pos_a[3]) == 0){
				miss = false;
				break;
			}
		}
		if(miss){
			return false;
		}
		count_a++;
	}
	for(const uint8_t *pos_b=oxm_b; pos_b < (const uint8_t*)oxm_b+len_b; pos_b+=4+pos_b[3]){
		count_a--;
	}
	if(count_a==0){
		return true;
	}
	return false;
}

/*
*	Compares 2 match oxms
*	Return 1 if a matches for b (b is wider than a)
*
*	@param *match_a - pointer to the first match field
*	@param *match_b - pointer to the second match field
*
*/
bool field_match13(const void *oxm_a, int len_a, const void *oxm_b, int len_b){
	uint32_t prereq_a = match_prereq(oxm_a, len_a);
	if ((prereq_a & PREREQ_INVALID) != 0){
		return false;
	}
	uintptr_t bhdr = (uintptr_t)oxm_b;
	while(bhdr < (uintptr_t)oxm_b + len_b){
		uint32_t bfield = ntohl(*(uint32_t*)bhdr);
		uintptr_t ahdr = (uintptr_t)oxm_a;
		while(ahdr < (uintptr_t)oxm_a + len_a){
			uint32_t afield = ntohl(*(uint32_t*)ahdr);
			const uint8_t *a = (const void*)ahdr;
			const uint8_t *b = (const void*)bhdr;
			if(bfield == afield) {
				if(OXM_HASMASK(bfield)){
					int length = OXM_LENGTH(bfield)/2;
					if(OXM_HASMASK(afield)){
						for(int i=0; i<length; i++){
							if ((a[4+length+i] & b[4+length+i]) != a[4+length+i]){
								return false;
							}
						}
					}
					for(int i=0; i<length; i++){
						if ((a[4+i] & b[4+length+i]) != b[4+i]){
							return false;
						}
					}
					break;
				}else if (memcmp(a+4, b+4, OXM_LENGTH(bfield))==0){
					break;
				}else{
					return false;
				}
			}
			switch(bfield){
				case OXM_OF_ETH_TYPE:
				{
					uint16_t eth_type = ntohs(*(uint16_t*)(bhdr+4));
					switch (eth_type){
						case 0x0800:
							if ((prereq_a & (PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)) != 0){
								return 0;
							}
							if ((prereq_a & PREREQ_ETH_TYPE_MASK) == PREREQ_IPV6){
								return 0;
							}
						break;
						
						case 0x86dd:
							if ((prereq_a & (PREREQ_ARP | PREREQ_MPLS | PREREQ_PBB)) != 0){
								return 0;
							}
							if ((prereq_a & PREREQ_ETH_TYPE_MASK) == PREREQ_IPV4){
								return 0;
							}
						break;
						
						case 0x0806:
							if ((prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_ARP) != 0) {
								return 0;
							}
						break;
						
						case 0x8847:
						case 0x8848:
							if ((prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_MPLS) != 0) {
								return 0;
							}
						break;
						
						case 0x88e7:
							if ((prereq_a & PREREQ_ETH_TYPE_MASK & ~PREREQ_PBB) != 0) {
								return 0;
							}
						break;
					}
				}
				break;
				
				case OXM_OF_IP_PROTO:
					switch(b[4]){
						case 1:
							if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_ICMPV4) != 0) {
								return 0;
							}
							break;
						case 6:
							if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_TCP) != 0) {
								return 0;
							}
							break;
						case 17:
							if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_UDP) != 0){
								return 0;
							}
							break;
						case 58:
							if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_ICMPV6) != 0){
								return 0;
							}
							break;
						case 132:
							if ((prereq_a & PREREQ_IP_PROTO_MASK & ~PREREQ_SCTP) != 0){
								return 0;
							}
							break;
					}
					break;
				case OXM_OF_ICMPV6_TYPE:
					switch(b[4]){
						case 135:
							if ((prereq_a & PREREQ_ND_MASK & ~PREREQ_ND_SLL) != 0){
								return 0;
							}
							break;
						case 136:
							if ((prereq_a & PREREQ_ND_MASK & ~PREREQ_ND_TLL) != 0){
								return 0;
							}
							break;
					}
					break;
			}
			ahdr += 4 + OXM_LENGTH(afield);
		}
		bhdr += 4 + OXM_LENGTH(bfield);
	}

	uint32_t prereq_b = match_prereq(oxm_b, len_b);
	if ((prereq_b & PREREQ_INVALID) != 0){
		return false;
	}
	// 0 means don't care
	if (((prereq_a & PREREQ_ETH_TYPE_MASK) | (prereq_b & PREREQ_ETH_TYPE_MASK)) != (prereq_a & PREREQ_ETH_TYPE_MASK)){
		return false;
	}
	if (((prereq_a & PREREQ_ND_MASK) | (prereq_b & PREREQ_ND_MASK)) != (prereq_a & PREREQ_ND_MASK)){
		return false;
	}
	if ((prereq_b & PREREQ_VLAN) != 0) {
		uintptr_t ahdr = (uintptr_t)oxm_a;
		while(ahdr < (uintptr_t)oxm_a + len_a){
			uint32_t afield = *(uint32_t*)(ahdr);
			switch(afield){
				case OXM_OF_VLAN_VID_W:
					if ((ntohs(*(uint16_t*)(ahdr+6)) & OFPVID13_PRESENT) != 0){
						break;
					}
				case OXM_OF_VLAN_VID:
					if (ntohs(*(uint16_t*)(ahdr+4)) == OFPVID13_NONE){
						return false;
					}
					break;
			}
			ahdr += 4 + OXM_LENGTH(afield);
		}
	}
	return true;
}

/*
*	Compares 2 ofp1.0 tuple match
*	Return 1 if a matches for b (b is wider than a)
*/
bool field_match10(const struct ofp_match *a, const struct ofp_match *b){
	uint32_t wild_a = ntohl(a->wildcards);
	uint32_t wild_b = ntohl(b->wildcards);
	if(wild_a == OFPFW_ALL){
		if(wild_b == OFPFW_ALL){
			return true;
		}else{
			return false;
		}
	}
	if(wild_b == OFPFW_ALL){
		return true;
	}
	uint32_t WILD_BITS = 0x3000FF;
	if(((wild_a&WILD_BITS)&(wild_b&WILD_BITS)) != (wild_b&WILD_BITS)){
		return false; // a has more wildcard bits
	}
	if((wild_a&OFPFW_NW_SRC_MASK) > (wild_b&OFPFW_NW_SRC_MASK)){
		return false;
	}
	if((wild_a&OFPFW_NW_DST_MASK) > (wild_b&OFPFW_NW_DST_MASK)){
		return false;
	}
	// below expects masked fields are filled with 0
	if((wild_b & OFPFW_DL_SRC) != 0){
		if(memcmp(a->dl_src, b->dl_src, OFP10_ETH_ALEN) != 0){
			return false;
		}
	}
	if((wild_b & OFPFW_DL_DST) != 0){
		if(memcmp(a->dl_dst, b->dl_dst, OFP10_ETH_ALEN) != 0){
			return false;
		}
	}
	if((wild_b & OFPFW_DL_VLAN) != 0){
		if(a->dl_vlan != b->dl_vlan){
			return false;
		}
	}
	// xxx: OFPFW_DL_VLAN_PCP?
	if((wild_b & OFPFW_NW_TOS) != 0){
		if(a->nw_tos != b->nw_tos){
			return false;
		}
	}
	if((wild_b & OFPFW_NW_PROTO) != 0){
		if(a->nw_proto != b->nw_proto){
			return false;
		}
	}
	uint8_t mlen = (wild_b & OFPFW_NW_SRC_MASK)>>OFPFW_NW_SRC_SHIFT;
	if((a->nw_src>>mlen) != (b->nw_src>>mlen)){
		return false;
	}
	mlen = (wild_b & OFPFW_NW_DST_MASK)>>OFPFW_NW_DST_SHIFT;
	if((a->nw_dst>>mlen) != (b->nw_dst>>mlen)){
		return false;
	}
	if((wild_b & OFPFW_TP_SRC) != 0){
		if(a->tp_src != b->tp_src){
			return false;
		}
	}
	if((wild_b & OFPFW_TP_DST) != 0){
		if(a->tp_dst != b->tp_dst){
			return false;
		}
	}
	return true;
}
