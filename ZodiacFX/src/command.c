/**
 * @file
 * command.c
 *
 * This file contains the command line functions
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
#include <inttypes.h>
#include "config_zodiac.h"
#include "command.h"
#include "conf_eth.h"
#include "eeprom.h"
#include "switch.h"
#include "openflow.h"
#include "of_helper.h"
#include "lwip/def.h"
#include "timers.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

#define RSTC_KEY  0xA5000000

// Global variables
extern struct zodiac_config Zodiac_Config;
extern struct fx_port_count fx_port_counts[MAX_PORTS];
extern struct fx_table_count fx_table_counts[MAX_TABLES];
extern struct fx_flow_count fx_flow_counts[MAX_FLOWS];
extern struct fx_flow_timeout fx_flow_timeouts[MAX_FLOWS];
extern struct fx_flow fx_flows[MAX_FLOWS];
extern int32_t ul_temp;
extern int iLastFlow;
extern int OF_Version;
extern bool masterselect;

// Local Variables
static uint8_t uCLIContext = 0;
struct arp_header arp_test;
uint8_t esc_char = 0;
int charcount = 0;
int charcount_last = 0;

// Internal Functions	
void saveConfig(void);
void command_root(char *command, char *param1, char *param2, char *param3);
void command_config(char *command, char *param1, char *param2, char *param3);
void command_openflow(char *command, char *param1, char *param2, char *param3);
void command_debug(char *command, char *param1, char *param2, char *param3);
void printintro(void);
void printhelp(void);

/*
*	Load the configuration settings from EEPROM 
*
*/
void loadConfig(void)
{
	eeprom_read();
	return;
}

/*
*	Save the configuration settings to EEPROM 
*
*/
void saveConfig(void)
{
	eeprom_write();
	return;
}

#define CMD_BUFLEN 64
static char cCommand[64] = {0};
static char cCommand_last[64] = {0};

static bool showintro = true;

/*
*	Main command line loop
*
*	@param str - pointer to the current command string
*	@param str_last - pointer to the last command string
*/
void task_command(void){
	char *str = cCommand;
	char *str_last = cCommand_last;

	char ch;
	char *command;
	char *param1;
	char *param2;
	char *param3;
	char *pch;
	
	while(udi_cdc_is_rx_ready()){
		ch = udi_cdc_getc();
		// Show the intro only on the first key press
		if (showintro == true){
			printintro();
			showintro = false;
			continue; // discard the input
		}	
		if (ch == 27) // Is this the start of an escape key sequence?
		{
			esc_char = 1;
			continue;
		}
		if (ch == 91 && esc_char == 1) // Second key in the escape key sequence?
		{
			esc_char = 2;
			continue;
		}
		if (ch == 65 && esc_char == 2 && charcount == 0)	// Last char for the escape sequence for the up arrow (ascii codes 27,91,65)
		{
			strcpy(str, str_last);
			charcount = charcount_last;
			printf("%s",str);
			esc_char = 0;
			return;		
		}
		
		if (ch == 13)	// Enter Key
		{
			printf("\r\n");
			str[charcount] = '\0';
			strcpy(str_last, str);
			charcount_last = charcount;
			pch = strtok (str," ");
			command = pch;
			pch = strtok (NULL, " ");
			param1 = pch;
			pch = strtok (NULL, " ");
			param2 = pch;
			pch = strtok (NULL, " ");
			param3 = pch;
			
			if (charcount > 0)
			{
				switch(uCLIContext)
				{
					case CLI_ROOT:
					command_root(command, param1, param2, param3);
					break;
					
					case CLI_CONFIG:
					command_config(command, param1, param2, param3);
					break;
					
					case CLI_OPENFLOW:
					command_openflow(command, param1, param2, param3);
					break;
					
					case CLI_DEBUG:
					command_debug(command, param1, param2, param3);
					break;
				};
			}
			
			switch(uCLIContext)
			{
				case CLI_ROOT:
				printf("%s# ",Zodiac_Config.device_name);
				break;
				
				case CLI_CONFIG:
				printf("%s(config)# ",Zodiac_Config.device_name);
				break;
				
				case CLI_OPENFLOW:
				printf("%s(openflow)# ",Zodiac_Config.device_name);
				break;
				
				case CLI_DEBUG:
				printf("%s(debug)# ",Zodiac_Config.device_name);
				break;
			};
			charcount = 0;
			str[0] = '\0';
			esc_char = 0;
			return;
			
		} else if ((ch == 127 || ch == 8) && charcount > 0)	// Backspace key
		{	
			charcount--;
			char tempstr[64];
			tempstr[0] = '\0';
			strncat(tempstr,str,charcount);
			strcpy(str, tempstr);
			printf("%c",ch); // echo to output
			esc_char = 0;
			return;
			
		} else if (charcount < 63 && ch > 31 && ch < 127 && esc_char == 0)	// Alphanumeric key
		{
			if(charcount < CMD_BUFLEN){ // xxx
				strncat(str,&ch,1);
			}
			charcount++;
			printf("%c",ch); // echo to output
			esc_char = 0;
			return;
		}
		
		if (esc_char > 0) esc_char = 0; // If the escape key wasn't up arrow (ascii 65) then clear to flag
	}
}

/*
*	Commands within the root context
*	
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_root(char *command, char *param1, char *param2, char *param3)
{
	// Change context
	if (strcmp(command, "config")==0){
		uCLIContext = CLI_CONFIG;
		return;
	}
	
	if (strcmp(command, "openflow")==0){
		uCLIContext = CLI_OPENFLOW;
		return;
	}
	
	if (strcmp(command, "debug")==0){
		uCLIContext = CLI_DEBUG;
		return;
	}

	// Display help
	if (strcmp(command, "help") == 0)
	{
		printhelp();
		return;

	}	
	// Display firmware version
	if (strcmp(command, "show") == 0 && strcmp(param1, "version") == 0)
	{
		printf("Firmware version: %s\r\n\n",VERSION);
		return;
	}
	
	// Display ports statics
	if (strcmp(command, "show") == 0 && strcmp(param1, "ports") == 0)
	{
		printf("\r\n-------------------------------------------------------------------------\r\n");
		for(int i=0;i<MAX_PORTS;i++){
			printf("\r\nPort %d\r\n",i+1);
			if((get_switch_status(i) & OFPPS13_LINK_DOWN) == 0){
				printf(" Status: UP\r\n");
			}else{
				printf(" Status: DOWN\r\n");
			}
			for (int x=0;x<MAX_VLANS;x++){
				if (Zodiac_Config.vlan_list[x].portmap[i] == 1){
					if (Zodiac_Config.vlan_list[x].uVlanType == 0) printf(" VLAN type: Unassigned\r\n");
					if (Zodiac_Config.vlan_list[x].uVlanType == 1) printf(" VLAN type: OpenFlow\r\n");
					if (Zodiac_Config.vlan_list[x].uVlanType == 2) printf(" VLAN type: Native\r\n");
					printf(" VLAN ID: %d\r\n", Zodiac_Config.vlan_list[x].uVlanID);
				}
			}
			sync_switch_port_counts(i);
			printf(" RX Bytes: %" PRIu64 "\r\n", fx_port_counts[i].rx_bytes);
			printf(" TX Bytes: %" PRIu64 "\r\n", fx_port_counts[i].tx_bytes);
			if (Zodiac_Config.of_port[i] == 1) printf(" RX Packets: %" PRIu64 "\r\n", fx_port_counts[i].rx_packets);
			if (Zodiac_Config.of_port[i] == 1) printf(" TX Packets: %" PRIu64 "\r\n", fx_port_counts[i].tx_packets);
			printf(" RX Dropped Packets: %" PRIu64 "\r\n", fx_port_counts[i].rx_dropped);
			printf(" TX Dropped Packets: %" PRIu64 "\r\n", fx_port_counts[i].tx_dropped);
			printf(" RX CRC Errors: %" PRIu64 "\r\n", fx_port_counts[i].rx_crc_err);
		}
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}
	
	// Display Config
	if (strcmp(command, "show")==0 && strcmp(param1, "status")==0){
		uint64_t totaltime = sys_get_ms64()/1000u;
		int day = totaltime/(24*3600);
		totaltime = totaltime%(24*3600);
		int hr = totaltime/3600;
		totaltime = totaltime%3600;
		int min = totaltime/60;
		int sec = totaltime%60;

		printf("\r\n-------------------------------------------------------------------------\r\n");
		printf("Device Status\r\n");
		printf(" Firmware Version: %s\r\n",VERSION);
		printf(" CPU Temp: %d C\r\n", (int)ul_temp);
		if (day > 1){
			printf(" Uptime: %d days, %02d:%02d:%02d", day, hr, min, sec);
		}else if (day > 0){
			printf(" Uptime: %d day, %02d:%02d:%02d", day, hr, min, sec);
		}else{
			printf(" Uptime: %02d:%02d:%02d", hr, min, sec);
		}
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}
	
	// Unknown Command
	printf("Unknown command\r\n");
	return;
}


static void sync_portmap(struct zodiac_config *config){
	// Create port map
	for(int i=0; i<MAX_PORTS; i++){
		config->of_port[i] = 0;
	}
	for (int v = 0;v < MAX_VLANS;v++){
		if (config->vlan_list[v].uActive == 1){
			for(int p=0; p<MAX_PORTS; p++){
				if (config->vlan_list[v].portmap[p] != 0){
					switch(config->vlan_list[v].uVlanType){
						case 1:
						config->of_port[p] = PORT_OPENFLOW; // Port is assigned to an OpenFlow VLAN
						break;
						
						case 2:
						config->of_port[p] = PORT_NATIVE; // Port is assigned to a Native VLAN
						break;
					}
				}
			}
		}
	}
}

/*
*	Commands within the config context
*	
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_config(char *command, char *param1, char *param2, char *param3)
{
	// Return to root context 
	if (strcmp(command, "exit")==0){
		uCLIContext = CLI_ROOT;
		return;
	}
	
	// Load config
	if (strcmp(command, "load")==0){
		loadConfig();
		return;
	}
	
	// Save config
	if (strcmp(command, "save")==0){
		saveConfig();
		return;
	}	
	
	// Display Config
	if (strcmp(command, "show")==0 && strcmp(param1, "config")==0){
		printf("\r\n-------------------------------------------------------------------------\r\n");
		printf("Configuration\r\n");
		printf(" Name: %s\r\n",Zodiac_Config.device_name);
		printf(" MAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]);
		printf(" IP Address: %d.%d.%d.%d\r\n" , Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1], Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]);
		printf(" Netmask: %d.%d.%d.%d\r\n" , Zodiac_Config.netmask[0], Zodiac_Config.netmask[1], Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]);
		printf(" Gateway: %d.%d.%d.%d\r\n" , Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1], Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]);
		printf(" OpenFlow Controller: %d.%d.%d.%d\r\n" , Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1], Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]);
		printf(" OpenFlow Port: %d\r\n" , Zodiac_Config.OFPort);
		if (Zodiac_Config.OFEnabled == OF_ENABLED) printf(" Openflow Status: Enabled\r\n");
		if (Zodiac_Config.OFEnabled == OF_DISABLED) printf(" Openflow Status: Disabled\r\n");
		if (Zodiac_Config.fail_mode == FAIL_MODE_SECURE) printf(" Failstate: Secure\r\n");
		if (Zodiac_Config.fail_mode == FAIL_MODE_STANDALONE) printf(" Failstate: Safe\r\n");
		if (Zodiac_Config.of_version == 1) {
			printf(" Force OpenFlow version: 1.0 (0x01)\r\n");
		} else if (Zodiac_Config.of_version == 4){
			printf(" Force OpenFlow version: 1.3 (0x04)\r\n");	
		} else {
			printf(" Force OpenFlow version: Disabled\r\n");
		}
		if (masterselect == true) printf(" Stacking Select: SLAVE\r\n");
		if (masterselect == false) printf(" Stacking Select: MASTER\r\n");
		printf(" Stacking Status: Unavailable\r\n");
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}	

	// Display Config
	if (strcmp(command, "show")==0 && strcmp(param1, "vlans")==0){
		int x;
		printf("\r\n\tVLAN ID\t\tName\t\t\tType\r\n");
		printf("-------------------------------------------------------------------------\r\n");
		for (x=0;x<MAX_VLANS;x++)
		{
			if (Zodiac_Config.vlan_list[x].uActive == 1) 
			{
				printf("\t%d\t\t'%s'\t\t",Zodiac_Config.vlan_list[x].uVlanID, Zodiac_Config.vlan_list[x].cVlanName);
				if (Zodiac_Config.vlan_list[x].uVlanType == 0) printf("Undefined\r\n");
				if (Zodiac_Config.vlan_list[x].uVlanType == 1) printf("OpenFlow\r\n");
				if (Zodiac_Config.vlan_list[x].uVlanType == 2) printf("Native\r\n");
			}
		}
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}

//
//
// VLAN commands
//
//

	// Add new VLAN
	if (strcmp(command, "add")==0 && strcmp(param1, "vlan")==0){
		for(int v=0; v<MAX_VLANS; v++){
			if(Zodiac_Config.vlan_list[v].uActive != 1){
				int namelen = strlen(param3);
				if(namelen > 15){
					printf("name length must be shorter than 16 characaters.\r\n");
					return;
				}
				int vlanid;
				if(1 != sscanf(param2, "%d", &vlanid)){
					printf("vlan id must be integer.\r\n");
					return;
				}
				Zodiac_Config.vlan_list[v].uActive = 1;
				Zodiac_Config.vlan_list[v].uVlanID = vlanid;
				snprintf(Zodiac_Config.vlan_list[v].cVlanName, 16, "%s", param3);
				printf("Added VLAN %d '%s'\r\n",Zodiac_Config.vlan_list[v].uVlanID, Zodiac_Config.vlan_list[v].cVlanName);
				return;
			}
		}
		// Can't find an empty VLAN slot
		printf("No more VLANs available\r\n");
		return;
	}
	
	// Delete an existing VLAN
	if (strcmp(command, "delete")==0 && strcmp(param1, "vlan")==0){
		int vlanid;
		sscanf(param2, "%d", &vlanid);
		for (int x=0;x<MAX_VLANS;x++){
			if(Zodiac_Config.vlan_list[x].uVlanID == vlanid){
				memset(&Zodiac_Config.vlan_list[x], 0, sizeof(struct virtlan));
				printf("VLAN %d deleted\r\n",vlanid);
				sync_portmap(&Zodiac_Config);
				return;
			}
		}
		printf("Unknown VLAN ID\r\n");
		return;
	}	

	// Set VLAN type
	if (strcmp(command, "set")==0 && strcmp(param1, "vlan-type")==0){
		int vlanid;
		sscanf(param2, "%d", &vlanid);
		for (int x=0;x<MAX_VLANS;x++){
			if(Zodiac_Config.vlan_list[x].uVlanID == vlanid){
				if(strcmp(param3, "openflow")==0){
					Zodiac_Config.vlan_list[x].uVlanType = 1;
					printf("VLAN %d set as OpenFlow\r\n",vlanid);
					sync_portmap(&Zodiac_Config);
					return;
				}
				if(strcmp(param3, "native")==0){
					Zodiac_Config.vlan_list[x].uVlanType = 2;
					printf("VLAN %d set as Native\r\n",vlanid);
					sync_portmap(&Zodiac_Config);
					return;
				}
				printf("Unknown VLAN type\r\n");
				return;
			}
		}
		printf("Unknown VLAN ID\r\n");
		return;
	}
	
	// Add port to VLAN
	if (strcmp(command, "add")==0 && strcmp(param1, "vlan-port")==0){
		int vlanid, port;
		sscanf(param2, "%d", &vlanid);
		sscanf(param3, "%d", &port);
		if (port < 1 || port > 4){
			printf("Invalid port number, ports are numbered 1 - 4\r\n");
			return;
		}
		// Check if the port is already assigned to a VLAN
		for (int x=0; x<MAX_VLANS; x++){
			if(Zodiac_Config.vlan_list[x].portmap[port-1] != 0){
				printf("Port %d is already assigned to VLAN %d\r\n", port, Zodiac_Config.vlan_list[x].uVlanID);
				return;
			}
		}
		// Assign the port to the requested VLAN
		for (int x=0; x<MAX_VLANS; x++){
			if(Zodiac_Config.vlan_list[x].uVlanID == vlanid){
				Zodiac_Config.vlan_list[x].portmap[port-1] = 1;
				printf("Port %d is now assigned to VLAN %d\r\n", port, vlanid);
				sync_portmap(&Zodiac_Config);
				return;
			}
		}
		printf("Unknown VLAN ID\r\n");
		return;
	}

	// Delete a port from a VLAN
	if (strcmp(command, "delete")==0 && strcmp(param1, "vlan-port")==0){
		int port;
		sscanf(param2, "%d", &port);
		if (port < 1 || port > 4){
			printf("Invalid port number, ports are numbered 1 - 4\r\n");
			return;
		}
		// Check if the port is already assigned to a VLAN
		for (int x=0;x<MAX_VLANS;x++){
			if(Zodiac_Config.vlan_list[x].portmap[port-1] != 0){
				Zodiac_Config.vlan_list[x].portmap[port-1] = 0;
				printf("Port %d has been removed from VLAN %d\r\n", port, Zodiac_Config.vlan_list[x].uVlanID);
				sync_portmap(&Zodiac_Config);
				return;
			}
		}
		printf("Port %d is not assigned to this VLAN\r\n", port);
		return;
	}

//
//
// Configuration commands
//
//
	
	// Set Device Name
	if (strcmp(command, "set")==0 && strcmp(param1, "name")==0)
	{
		memset(Zodiac_Config.device_name, 0, 16);
		uint8_t namelen = strlen(param2);
		if (namelen > 15 ) namelen = 15; // Make sure name is less then 16 characters
		memcpy(Zodiac_Config.device_name, param2, namelen);
		printf("Device name set to '%s'\r\n",Zodiac_Config.device_name);
		return;
	}
	
	// Set MAC Address
	if (strcmp(command, "set")==0 && strcmp(param1, "mac-address")==0)
	{
		unsigned int mac1,mac2,mac3,mac4,mac5,mac6;
		if (strlen(param2) != 17 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%x:%x:%x:%x:%x:%x", &mac1, &mac2, &mac3, &mac4, &mac5, &mac6);
		Zodiac_Config.MAC_address[0] = mac1;
		Zodiac_Config.MAC_address[1] = mac2;
		Zodiac_Config.MAC_address[2] = mac3;
		Zodiac_Config.MAC_address[3] = mac4;		
		Zodiac_Config.MAC_address[4] = mac5;		
		Zodiac_Config.MAC_address[5] = mac6;		
		printf("MAC Address set to %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\r\n",Zodiac_Config.MAC_address[0], Zodiac_Config.MAC_address[1], Zodiac_Config.MAC_address[2], Zodiac_Config.MAC_address[3], Zodiac_Config.MAC_address[4], Zodiac_Config.MAC_address[5]);
		return;
	}

	// Set IP Address
	if (strcmp(command, "set")==0 && strcmp(param1, "ip-address")==0)
	{
		int ip1,ip2,ip3,ip4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r");
			return;
		}
		sscanf(param2, "%d.%d.%d.%d", &ip1, &ip2,&ip3,&ip4);
		Zodiac_Config.IP_address[0] = ip1;
		Zodiac_Config.IP_address[1] = ip2;
		Zodiac_Config.IP_address[2] = ip3;
		Zodiac_Config.IP_address[3] = ip4;
		printf("IP Address set to %d.%d.%d.%d\r\n" , Zodiac_Config.IP_address[0], Zodiac_Config.IP_address[1], Zodiac_Config.IP_address[2], Zodiac_Config.IP_address[3]);
		return;
	}

	// Set Netmask Address
	if (strcmp(command, "set")==0 && strcmp(param1, "netmask")==0)
	{
		uint8_t nm1,nm2,nm3,nm4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%"SCNu8".%"SCNu8".%"SCNu8 ".%"SCNu8, &nm1, &nm2,&nm3,&nm4);
		Zodiac_Config.netmask[0] = nm1;
		Zodiac_Config.netmask[1] = nm2;
		Zodiac_Config.netmask[2] = nm3;
		Zodiac_Config.netmask[3] = nm4;
		printf("IP Address set to %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\r\n" , Zodiac_Config.netmask[0], Zodiac_Config.netmask[1], Zodiac_Config.netmask[2], Zodiac_Config.netmask[3]);
		return;
	}
	
	// Set Gateway Address
	if (strcmp(command, "set")==0 && strcmp(param1, "gateway")==0)
	{
		uint8_t gw1,gw2,gw3,gw4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8, &gw1, &gw2,&gw3,&gw4);
		Zodiac_Config.gateway_address[0] = gw1;
		Zodiac_Config.gateway_address[1] = gw2;
		Zodiac_Config.gateway_address[2] = gw3;
		Zodiac_Config.gateway_address[3] = gw4;
		printf("IP Address set to %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\r\n" , Zodiac_Config.gateway_address[0], Zodiac_Config.gateway_address[1], Zodiac_Config.gateway_address[2], Zodiac_Config.gateway_address[3]);
		return;
	}

	// Set OpenFlow Controller IP Address
	if (strcmp(command, "set")==0 && strcmp(param1, "of-controller")==0)
	{
		uint8_t oc1,oc2,oc3,oc4;
		if (strlen(param2) > 15 )
		{
			printf("incorrect format\r\n");
			return;
		}
		sscanf(param2, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8, &oc1,&oc2,&oc3,&oc4);
		Zodiac_Config.OFIP_address[0] = oc1;
		Zodiac_Config.OFIP_address[1] = oc2;
		Zodiac_Config.OFIP_address[2] = oc3;
		Zodiac_Config.OFIP_address[3] = oc4;
		printf("OpenFlow Server address set to %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\r\n" , Zodiac_Config.OFIP_address[0], Zodiac_Config.OFIP_address[1], Zodiac_Config.OFIP_address[2], Zodiac_Config.OFIP_address[3]);
		return;
	}
	
	// Set OpenFlow Controller Port
	if (strcmp(command, "set")==0 && strcmp(param1, "of-port")==0)
	{
		sscanf(param2, "%d", &Zodiac_Config.OFPort);
		printf("OpenFlow Port set to %d\r\n" , Zodiac_Config.OFPort);
		return;
	}
	
	// Reset the device to a basic configuration
	if (strcmp(command, "factory")==0 && strcmp(param1, "reset")==0)
	{
		struct zodiac_config reset_config = 
		{
			"Zodiac_FX",		// Name
			{0,0,0,0,0,0},		// MAC Address
			{10,0,1,99},			// IP Address
			{255,255,255,0},		// Netmask
			{10,0,1,1},			// Gateway Address
			{10,0,1,8},			// IP Address of the SDN Controller
			6633,				// TCP port of SDN Controller
			1					// OpenFlow enabled
		};
		memset(reset_config.vlan_list, 0, sizeof(struct virtlan)* MAX_VLANS); // Clear vlan array
		
		// Config VLAN 100
		sprintf(reset_config.vlan_list[0].cVlanName, "Openflow");	// Vlan name
		reset_config.vlan_list[0].portmap[0] = 1;		// Assign port 1 to this vlan
		reset_config.vlan_list[0].portmap[1] = 1;		// Assign port 2 to this vlan		
		reset_config.vlan_list[0].portmap[2] = 1;		// Assign port 3 to this vlan
		reset_config.vlan_list[0].uActive = 1;		// Vlan is active
		reset_config.vlan_list[0].uVlanID = 100;	// Vlan ID is 100
		reset_config.vlan_list[0].uVlanType = 1;	// Set as an Openflow Vlan
		reset_config.vlan_list[0].uTagged = 0;		// Set as untagged	
		
		// Config VLAN 200
		sprintf(reset_config.vlan_list[1].cVlanName, "Controller");
		reset_config.vlan_list[1].portmap[3] = 1;		// Assign port 4 to this vlan
		reset_config.vlan_list[1].uActive = 1;		// Vlan is active
		reset_config.vlan_list[1].uVlanID = 200;	// Vlan ID is 200
		reset_config.vlan_list[1].uVlanType = 2;	// Set as an Native Vlan
		reset_config.vlan_list[1].uTagged = 0;		// Set as untagged			
		
		// Set ports
		sync_portmap(&reset_config);
		
		// Failstate
		reset_config.fail_mode = FAIL_MODE_SECURE;			// Failstate Secure
		
		// Force OpenFlow version
		reset_config.of_version = 0;			// Force version disabled
		
		memcpy(reset_config.MAC_address, Zodiac_Config.MAC_address, 6);		// Copy over existng MAC address so it is not reset
		memcpy(&Zodiac_Config, &reset_config, sizeof(struct zodiac_config));
		saveConfig();
		return;
	}

	// Set Failstate
	if (strcmp(command, "set")==0 && strcmp(param1, "failstate")==0)
	{
		if (strcmp(param2, "secure")==0){
			Zodiac_Config.fail_mode = FAIL_MODE_SECURE;
			printf("Failstate set to Secure\r\n");
		} else if (strcmp(param2, "safe")==0){
			Zodiac_Config.fail_mode = FAIL_MODE_STANDALONE;
			printf("Failstate set to Safe\r\n");
		} else {
			printf("Invalid failstate type\r\n");
		}
		return;
	}

	// Set Force OpenFlow Version
	if (strcmp(command, "set")==0 && strcmp(param1, "of-version")==0)
	{
		int tmp_version = -1;
		sscanf(param2, "%d", &tmp_version);
		if (tmp_version == 0){
				printf("Force OpenFlow version Disabled\r\n");
				Zodiac_Config.of_version = 0;
			} else if (tmp_version == 1){
				printf("Force OpenFlow version set to 1.0 (0x01)\r\n");
				Zodiac_Config.of_version = 1;
			} else if (tmp_version == 4){
				printf("Force OpenFlow version set to 1.3 (0x04)\r\n");
				Zodiac_Config.of_version = 4;
			} else {
				printf("Invalid OpenFlow version, valid options are 0, 1 or 4\r\n");
				Zodiac_Config.of_version = 0;
		}
		return;
	}
		
	// Unknown Command
	printf("Unknown command\r\n");
	return;	
}


/*
*	Commands within the OpenFlow context
*	
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_openflow(char *command, char *param1, char *param2, char *param3)
{
	if (strcmp(command, "exit")==0){
		uCLIContext = CLI_ROOT;
		return;
	}

	// Openflow Flows
	if (strcmp(command, "show") == 0 && strcmp(param1, "flows") == 0){
		printf("\r\n-------------------------------------------------------------------------\r\n");
		for(uint8_t t=0; t<MAX_TABLES; t++){
			for(int32_t priority=0xffffu; priority>=0; priority--){
				for(int i=0; i<iLastFlow; i++){
					if((fx_flows[i].send_bits & FX_FLOW_ACTIVE) == 0){
						continue;
					}
					if(fx_flows[i].table_id != t){
						continue;
					}
					if(fx_flows[i].priority != priority){
						continue;
					}
					// OpenFlow v1.3 (0x04) Flow Table
					if( OF_Version == 4){
						printf("\r\nFlow %d\r\n",i+1);
						printf(" Match:\r\n");
						const uint8_t *pos = fx_flows[i].oxm;
						while (pos < (const uint8_t *)fx_flows[i].oxm + fx_flows[i].oxm_length){
							switch(pos[2]>>1){
								case OFPXMT13_OFB_IN_PORT:
								printf("  In Port: %"PRIx32"\r\n", ntohl(get32((uintptr_t)pos + 4)));
								break;
							
								case OFPXMT13_OFB_ETH_DST:
								printf("  Destination MAC: %02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"\r\n",
									pos[4], pos[5], pos[6], pos[7], pos[8], pos[9]);
								break;
							
								case OFPXMT13_OFB_ETH_SRC:
								printf("  Source MAC: %02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"\r\n",
									pos[4], pos[5], pos[6], pos[7], pos[8], pos[9]);
								break;

								case OFPXMT13_OFB_ETH_TYPE:
								{
									uint16_t eth_type = ntohs(get16((uintptr_t)pos + 4));
									if (eth_type == 0x0806 )printf("  ETH Type: ARP\r\n");
									else if (eth_type == 0x0800 )printf("  ETH Type: IPv4\r\n");
									else if (eth_type == 0x86dd )printf("  ETH Type: IPv6\r\n");
									else printf("  ETH Type: %04"PRIx16"\r\n", eth_type);
								}
								break;

								case OFPXMT13_OFB_IP_PROTO:
								if (pos[4] == 1 )printf("  IP Protocol: ICMP\r\n");
								else if (pos[4] == 6 )printf("  IP Protocol: TCP\r\n");
								else if (pos[4] == 17 )printf("  IP Protocol: UDP\r\n");
								else printf("  IP Protocol: %"PRIu8"\r\n", pos[4]);
								break;

								case OFPXMT13_OFB_IPV4_SRC:
								printf("  Source IP: %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\r\n",
									pos[4], pos[5], pos[6], pos[7]);
								break;
							
								case OFPXMT13_OFB_IPV4_DST:
								printf("  Destination IP: %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\r\n",
									pos[4], pos[5], pos[6], pos[7]);
								break;

								case OFPXMT13_OFB_IPV6_SRC:
								printf("  Source IP: %04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16"\r\n",
									get16((uintptr_t)pos+4),
									get16((uintptr_t)pos+6),
									get16((uintptr_t)pos+8),
									get16((uintptr_t)pos+10),
									get16((uintptr_t)pos+12),
									get16((uintptr_t)pos+14),
									get16((uintptr_t)pos+16),
									get16((uintptr_t)pos+18));
								break;
							
								case OFPXMT13_OFB_IPV6_DST:
								printf("  Destination IP: %04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16":%04"PRIu16"\r\n",
									get16((uintptr_t)pos+4),
									get16((uintptr_t)pos+6),
									get16((uintptr_t)pos+8),
									get16((uintptr_t)pos+10),
									get16((uintptr_t)pos+12),
									get16((uintptr_t)pos+14),
									get16((uintptr_t)pos+16),
									get16((uintptr_t)pos+18));
								break;
							
								case OFPXMT13_OFB_TCP_SRC:
								printf("  Source TCP Port: %d\r\n", get16((uintptr_t)pos + 4));
								break;

								case OFPXMT13_OFB_TCP_DST:
								printf("  Destination TCP Port: %d\r\n", get16((uintptr_t)pos + 4));
								break;

								case OFPXMT13_OFB_UDP_SRC:
								printf("  Source UDP Port: %d\r\n", get16((uintptr_t)pos + 4));
								break;

								case OFPXMT13_OFB_UDP_DST:
								printf("  Destination UDP Port: %d\r\n", get16((uintptr_t)pos + 4));
								break;
							
								case OFPXMT13_OFB_VLAN_VID:
								printf("  VLAN ID: %d\r\n", 0x0FFF & get16((uintptr_t)pos + 4));
								break;
							
							};
							pos += 4 + pos[3];
						}
						printf("\r Attributes:\r\n");
						printf("  Priority: %d\t\t\tDuration: %d secs\r\n",
							fx_flows[i].priority, (sys_get_ms()-fx_flow_timeouts[i].init) / 1000u);
						printf("  Hard Timeout: %d secs\t\t\tIdle Timeout: %d secs\r\n", 
							fx_flow_timeouts[i].hard_timeout, fx_flow_timeouts[i].idle_timeout);
						printf("  Byte Count: %d\t\t\tPacket Count: %d\r\n",
							fx_flow_counts[i].byte_count, fx_flow_counts[i].packet_count);
						if (fx_flows[i].ops != NULL){
							printf("\r Instructions:\r\n");
							uintptr_t pos = fx_flows[i].ops;
							while(pos < (uintptr_t)fx_flows[i].ops + fx_flows[i].ops_length){
								struct ofp13_instruction inst;
								memcpy(&inst, (void*)pos, sizeof(inst));
								if(ntohs(inst.type) == OFPIT13_APPLY_ACTIONS){
									printf("  Apply Actions:\r\n");
									struct ofp13_instruction_actions inst_act;
									memcpy(&inst_act, (void*)pos, sizeof(inst_act));
									
									uintptr_t pos_act = pos + offsetof(struct ofp13_instruction_actions, actions);
									while(pos_act < pos + ntohs(inst_act.len)){
										struct ofp13_action_header act_hdr;
										memcpy(&act_hdr, (void*)pos_act, sizeof(act_hdr));
										
										if (htons(act_hdr.type) == OFPAT13_OUTPUT){
											struct ofp13_action_output act_output;
											memcpy(&act_output, (void*)pos_act, sizeof(act_output));
											
											if (htonl(act_output.port) < OFPP13_MAX){
												printf("   Output Port: %d\r\n", htonl(act_output.port));
											} else if (htonl(act_output.port) == OFPP13_CONTROLLER){
												printf("   Output: CONTROLLER \r\n");
											} else if (htonl(act_output.port) == OFPP13_FLOOD){
												printf("   Output: FLOOD \r\n");
											}
											// XXX: implement more
										}
										if (htons(act_hdr.type) == OFPAT13_SET_FIELD){
											const uint8_t *oxm = (void*)(pos_act + offsetof(struct ofp13_action_set_field, field));
											switch(oxm[2]>>1){
												case OFPXMT13_OFB_VLAN_VID:
												printf("   Set VLAN ID: %d\r\n", 0x0fff & get16((uintptr_t)oxm+4));
												break;
											// XXX: implement more
											};
										}
										pos_act += htons(act_hdr.len);
									}
								}
								pos += htons(inst.len);
							}
						}
					}
				}
			}
		}
		if(iLastFlow == 0){
			printf("No Flows installed!\r\n");
		}
		printf("\r\n-------------------------------------------------------------------------\r\n\n");
		return;
	}
	
	// Openflow status
	if (strcmp(command, "show") == 0 && strcmp(param1, "status") == 0)
	{
		printf("\r\n-------------------------------------------------------------------------\r\n");
		printf("OpenFlow Status\r");
		if (Zodiac_Config.OFEnabled == OF_DISABLED){
			printf(" Status: Disabled\r\n");
		} else if (switch_negotiated()){
			printf(" Status: Connected\r\n");
		} else {
			printf(" Status: Disconnected\r\n");
		}
		if (OF_Version == 1) printf(" Version: 1.0 (0x01)\r\n");
		if (OF_Version == 4) printf(" Version: 1.3 (0x04)\r\n");
		printf(" No tables: %d\r\n", MAX_TABLES);
		printf(" No flows: %d\r\n",iLastFlow);
		uint64_t lookup = 0;
		uint64_t matched = 0;
		for(uint8_t i=0; i<MAX_TABLES; i++){
			lookup += fx_table_counts[i].lookup;
			matched += fx_table_counts[i].matched;
		}
		printf(" Aggregated table lookups: %"PRIu64"\r\n", lookup);
		printf(" Aggregated table matches: %"PRIu64"\r\n", matched);
		
		printf("\r\n-------------------------------------------------------------------------\r\n");
		return;
	}

	// Enable OpenFlow
	if (strcmp(command, "enable")==0)
	{

		Zodiac_Config.OFEnabled = OF_ENABLED;
		enableOF();
		printf("Openflow Enabled\r\n");
		return;
	}

	// Disable OpenFlow	
	if (strcmp(command, "disable")==0)
	{
		Zodiac_Config.OFEnabled = OF_DISABLED;
		disableOF();
		printf("Openflow Disabled\r\n");
		return;
	}

	// Clear the flow table
	if (strcmp(command, "clear")==0 && strcmp(param1, "flows")==0){
		printf("Clearing flow table, %d flow deleted.\r\n", iLastFlow);
		for(int i=0; i<iLastFlow; i++){
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
		return;
	}

	// Unknown Command
	printf("Unknown command\r\n");
	return;	
}

/*
*	Commands within the debug context
*	
*	@param command - pointer to the command string
*	@param param1 - pointer to parameter 1
*	@param param2- pointer to parameter 2
*	@param param2 - pointer to parameter 3
*/
void command_debug(char *command, char *param1, char *param2, char *param3)
{
	if (strcmp(command, "exit")==0){
		uCLIContext = CLI_ROOT;
		return;
	}
		
	if (strcmp(command, "read")==0)
	{
		int n = switch_read(atoi(param1));
		printf("Register %d = 0x%.2X\r\n\n", atoi(param1), n);
		return;
	}

	if (strcmp(command, "write")==0)
	{
		switch_write(atoi(param1),atoi(param2));
		int n = switch_read(atoi(param1));
		printf("Register %d = 0x%.2X\r\n\n", atoi(param1),n);
		return;
	}

	if (strcmp(command, "spi")==0)
	{
		stack_write(atoi(param1));
		return;
	}

	if (strcmp(command, "restart")==0)
	{
		rstc_start_software_reset(RSTC);	// Need to fix this, board resets but can't connect to CLI again
		while (1);
	}
	
	// Unknown Command response
	printf("Unknown command\r\n");
	return;	
}

/*
*	Print the intro screen
*	ASCII art generated from http://patorjk.com/software/taag/
*
*/
void printintro(void)
{	
	printf("\r\n");
	printf(" _____             ___               _______  __\r\n");
	printf("/__  /  ____  ____/ (_)___ ______   / ____/ |/ /\r\n");
	printf("  / /  / __ \\/ __  / / __ `/ ___/  / /_   |   /\r\n");
	printf(" / /__/ /_/ / /_/ / / /_/ / /__   / __/  /   |  \r\n");
	printf("/____/\\____/\\__,_/_/\\__,_/\\___/  /_/    /_/|_| \r\n");
	printf("\t    by Northbound Networks\r\n");
	printf("\r\n\n");
	printf("Type 'help' for a list of available commands\r\n");
	return;
}

/*
*	Print a list of available commands
*	
*
*/
void printhelp(void)
{
	printf("\r\n");
	printf("The following commands are currently available:\r\n");
	printf("\r\n");
	printf("Base:\r\n");
	printf(" config\r\n");
	printf(" openflow\r\n");
	printf(" debug\r\n");
	printf(" show ports\r\n");
	printf(" show status\r\n");
	printf(" show version\r\n");
	printf("\r\n");
	printf("Config:\r\n");
	printf(" load\r\n");
	printf(" save\r\n");
	printf(" show config\r\n");
	printf(" show vlans\r\n");
	printf(" set name <name>\r\n");
	printf(" set mac-address <mac address>\r\n");
	printf(" set ip-address <ip address>\r\n");
	printf(" set netmask <netmasks>\r\n");
	printf(" set gateway <gateway ip address>\r\n");
	printf(" set of-controller <openflow controller ip address>\r\n");
	printf(" set of-port <openflow controller tcp port>\r\n");
	printf(" set failstate <secure|safe>\r\n");
	printf(" add vlan <vlan id> <vlan name>\r\n");
	printf(" delete vlan <vlan id>\r\n");
	printf(" set vlan-type <openflow|native>\r\n");
	printf(" add vlan-port <vlan id> <port>\r\n");
	printf(" delete vlan-port <port>\r\n");
	printf(" factory reset\r\n");
	printf(" set of-version <version(0|1|4)>\r\n");
	printf(" exit\r\n");
	printf("\r\n");
	printf("OpenFlow:\r\n");
	printf(" show status\r\n");
	printf(" show flows\r\n");
	printf(" enable\r\n");
	printf(" disable\r\n");
	printf(" clear flows\r\n");
	printf(" exit\r\n");
	printf("\r\n");
	printf("Debug:\r\n");
	printf(" read <register>\r\n");
	printf(" write <register> <value>\r\n");
	printf(" exit\r\n");
	printf("\r\n");
	return;
}