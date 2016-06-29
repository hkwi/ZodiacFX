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

static uint32_t crc32(uint8_t *data, uint16_t length)
{
	// RFC 3309
	uint32_t crc_c[256] = {
		0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
		0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
		0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
		0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
		0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
		0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
		0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
		0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
		0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
		0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
		0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
		0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
		0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
		0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
		0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
		0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
		0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
		0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
		0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
		0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
		0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
		0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
		0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
		0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
		0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
		0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
		0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
		0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
		0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
		0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
		0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
		0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
		0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
		0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
		0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
		0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
		0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
		0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
		0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
		0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
		0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
		0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
		0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
		0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
		0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
		0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
		0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
		0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
		0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
		0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
		0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
		0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
		0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
		0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
		0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
		0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
		0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
		0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
		0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
		0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
		0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
		0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
		0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
		0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
	};

	uint32_t crc32 = 0xffffffff;
	for ( size_t i = 0; i < length; i++ ) {
		crc32 = ( crc32 >> 8 ) ^ crc_c[ ( crc32 ^ ( data[ i ] ) ) & 0xFF ];
	}
	crc32 = ( ~crc32 ) & 0xffffffff;
	return crc32;
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
	if (IPH_PROTO(iphdr) == 132){ // IP_PROTO_SCTP
		uint8_t *sctp = p_uc_data + payload_offset;
		memset(sctp+8, 0, 4); // clear checksum
		uint32_t c = crc32(sctp, payload_length);
		sctp[8] = c & 0xff;
		sctp[9] = (c>>8) & 0xff;
		sctp[10] = (c>>16) & 0xff;
		sctp[11] = (c>>24) & 0xff;
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
	if (oob->ipv6_tp_type == 132){ // IP6_NEXTH_SCTP
		uint8_t *sctp = p_uc_data + oob->ipv6_tp_offset;
		memset(sctp+8, 0, 4); // clear checksum
		uint32_t c = crc32(sctp, packet_size - oob->ipv6_tp_offset);
		sctp[8] = c & 0xff;
		sctp[9] = (c>>8) & 0xff;
		sctp[10] = (c>>16) & 0xff;
		sctp[11] = (c>>24) & 0xff;
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
