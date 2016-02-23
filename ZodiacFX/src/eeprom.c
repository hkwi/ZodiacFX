/**
 * @file
 * eeprom.c
 *
 * This file contains the EEPROM functions for saving configuration settings
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
#include "eeprom.h"
#include "command.h"

/** TWI Bus Clock 100kHz */
#define TWI_CLK     100000
/** Address of AT24C chips */
#define AT24C_ADDRESS           0x50
#define EEPROM_MEM_ADDR_LENGTH  1
/** Data to be sent */

// Global variables
extern struct zodiac_config Zodiac_Config;

/*
*	Initialise the TWI interface to the EEPROM
*
*/
void eeprom_init(void)
{
	twi_options_t opt;
	
	pmc_enable_periph_clk(ID_TWI0);
	
	/* Configure the options of TWI driver */
	opt.master_clk = sysclk_get_cpu_hz();
	opt.speed      = TWI_CLK;
	
	if (twi_master_init(TWI0, &opt) != TWI_SUCCESS) {
			printf("-E-\tTWI master initialization failed.\r\n");
			return;
	}

	return;
}

/*
*	EEROM write function
*
*/
int eeprom_write(void)
{
	twi_packet_t packet_tx = {
		.addr = {0, 0, 0},
		.addr_length = EEPROM_MEM_ADDR_LENGTH,
		.buffer = &Zodiac_Config,
		.length = sizeof(Zodiac_Config),
		.chip = AT24C_ADDRESS,
	};

	printf("Writing Configuration to EEPROM (%d bytes)\r\n", packet_tx.length);
	
	if (twi_master_write(TWI0, &packet_tx) != TWI_SUCCESS)
	{
		printf("TWI master write packet failed.\r\n");
		return -1;
	}
	
	printf("Done!\r");
	return 0;

}

/*
*	EEROM read function
*
*/
int eeprom_read(void){
	/* Configure the data packet to be received */
	twi_packet_t packet_rx = {
		.addr = {0, 0, 0},
		.addr_length = EEPROM_MEM_ADDR_LENGTH,
		.buffer = &Zodiac_Config,
		.length = sizeof(Zodiac_Config),
		.chip = AT24C_ADDRESS,
	};

	printf("Reading Configuration from EEPROM (%d bytes)\r\n", packet_rx.length);
	
	if (twi_master_read(TWI0, &packet_rx) != TWI_SUCCESS)
	{
		printf("-1-\tTWI master read packet failed.\r\n");
		return -1;
	}
	
	printf("Done!\r\n");
	return 0;
}

