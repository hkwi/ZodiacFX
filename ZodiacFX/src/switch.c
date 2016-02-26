/**
 * @file
 * switch.c
 *
 * This file contains the initialization and functions for KSZ8795
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
#include <stdlib.h>
#include <string.h>
#include "openflow.h"
#include "switch.h"
#include "conf_eth.h"
#include "command.h"

#include "ksz8795clx/ethernet_phy.h"
#include "netif/etharp.h"

extern struct zodiac_config Zodiac_Config;
extern int OF_Version;

/** The GMAC driver instance */
gmac_device_t gs_gmac_dev = {
	.p_hw = GMAC,
};

/* SPI clock setting (Hz). */
static uint32_t gs_ul_spi_clock = 500000;

/* GMAC HW configurations */
#define BOARD_GMAC_PHY_ADDR 0
/** First Status Command Register - Second Dummy Data */
#define USART_SPI                   USART0
#define USART_SPI_DEVICE_ID         1
#define USART_SPI_BAUDRATE          1000000

/* Chip select. */
#define SPI_CHIP_SEL 0
#define SPI_CHIP_PCS spi_get_pcs(SPI_CHIP_SEL)
/* Clock polarity. */
#define SPI_CLK_POLARITY 0
/* Clock phase. */
#define SPI_CLK_PHASE 0
/* Delay before SPCK. */
#define SPI_DLYBS 0x40
/* Delay between consecutive transfers. */
#define SPI_DLYBCT 0x10

uint8_t stats_rr = 0;

void spi_master_initialize(void);
void spi_slave_initialize(void);

struct usart_spi_device USART_SPI_DEVICE = {
	 /* Board specific select ID. */
	 .id = USART_SPI_DEVICE_ID
 };

/*
*	Initialise the SPI interface for the switch
*
*/
void spi_init(void)
{
	/* Config the USART_SPI for KSZ8795 interface */
	usart_spi_init(USART_SPI);
	usart_spi_setup_device(USART_SPI, &USART_SPI_DEVICE, SPI_MODE_3, USART_SPI_BAUDRATE, 0);
	usart_spi_enable(USART_SPI);
}

/*
*	Write to the SPI stacking interface
*
*/
void stack_write(uint8_t value)
{
	uint8_t uc_pcs;
	static uint16_t data;
	
	for (int i = 0; i < 16; i++) {
		spi_write(SPI_MASTER_BASE, value + i, 0, 0);
		/* Wait transfer done. */
		while ((spi_read_status(SPI_MASTER_BASE) & SPI_SR_RDRF) == 0);
		spi_read(SPI_MASTER_BASE, &data, &uc_pcs);
		printf("%d , %d\r", data, ioport_get_pin_level(SPI_IRQ1));
	}
	return;
} 

/*
*	Initialise the SPI interface to MASTER or SLAVE based on the stacking jumper
*
*/
void stacking_init(bool master)
{
	if (master){
		spi_slave_initialize();
	} else {
		spi_master_initialize();
	}
	return;
}

/*
*	Initialise the SPI interface as a SLAVE
*
*/
void spi_slave_initialize(void)
{	
	NVIC_DisableIRQ(SPI_IRQn);
	NVIC_ClearPendingIRQ(SPI_IRQn);
	NVIC_SetPriority(SPI_IRQn, 0);
	NVIC_EnableIRQ(SPI_IRQn);
	
	/* Configure an SPI peripheral. */
	spi_enable_clock(SPI_SLAVE_BASE);
	spi_disable(SPI_SLAVE_BASE);
	spi_reset(SPI_SLAVE_BASE);
	spi_set_slave_mode(SPI_SLAVE_BASE);
	spi_disable_mode_fault_detect(SPI_SLAVE_BASE);
	spi_set_peripheral_chip_select_value(SPI_SLAVE_BASE, SPI_CHIP_PCS);
	spi_set_clock_polarity(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CLK_POLARITY);
	spi_set_clock_phase(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CLK_PHASE);
	spi_set_bits_per_transfer(SPI_SLAVE_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_8_BIT);
	spi_enable_interrupt(SPI_SLAVE_BASE, SPI_IER_RDRF);
	spi_enable(SPI_SLAVE_BASE);
}

/*
*	Initialise the SPI interface as a MASTER
*
*/
void spi_master_initialize(void)
{
	/* Configure an SPI peripheral. */
	spi_enable_clock(SPI_MASTER_BASE);
	spi_disable(SPI_MASTER_BASE);
	spi_reset(SPI_MASTER_BASE);
	spi_set_master_mode(SPI_MASTER_BASE);
	spi_disable_mode_fault_detect(SPI_MASTER_BASE);
	spi_disable_loopback(SPI_MASTER_BASE);
	spi_set_peripheral_chip_select_value(SPI_MASTER_BASE, SPI_CHIP_PCS);
	spi_set_fixed_peripheral_select(SPI_MASTER_BASE);
	spi_disable_peripheral_select_decode(SPI_MASTER_BASE);
	
	spi_set_transfer_delay(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_DLYBS, SPI_DLYBCT);
	spi_set_bits_per_transfer(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CSR_BITS_8_BIT);
	spi_set_baudrate_div(SPI_MASTER_BASE, SPI_CHIP_SEL, (sysclk_get_cpu_hz() / gs_ul_spi_clock));	
	spi_configure_cs_behavior(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CS_KEEP_LOW);
	spi_set_clock_polarity(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CLK_POLARITY);
	spi_set_clock_phase(SPI_MASTER_BASE, SPI_CHIP_SEL, SPI_CLK_PHASE);

	spi_enable(SPI_MASTER_BASE);
}

/*
*	SPI interface IRQ handler
*	Used to receive data from the stacking interface
*
*/
void SPI_Handler(void)
{
	static uint16_t data;
	uint8_t uc_pcs;

	spi_read(SPI_SLAVE_BASE, &data, &uc_pcs);
	if (data == 5) ioport_set_pin_level(SPI_IRQ1, true);
	if (data == 8) ioport_set_pin_level(SPI_IRQ1, false);
	printf("%d", data);
	data += 1;
	spi_write(SPI_SLAVE_BASE,data, 0, 0);
	printf("\r");
	return;
}

static void encode_spi_reg01(bool read, uint8_t addr, uint8_t *reg){
	reg[0] = 0x40;
	if(read){
		reg[0] |= 0x20;
	}
	if(addr & 0x80){
		reg[0] |= 0x01;
	}
	reg[1] = addr<<1;
}

/*
*	Read from the switch registers
*
* SPI read cycle
*      |         reg[0]        |         reg[1]        |
* S_DI | 0  1  1 __ __ __ __ A7 A6 A5 A4 A3 A2 A1 A0 TR
* S_DO |                                                D7 D6 D5 D4 D3 D2 D1 D0
*/
uint64_t switch_read(uint8_t addr)
{
	uint8_t reg[2];
	if (addr < 128) {
		reg[0] = 96;
	} else {
		reg[0] = 97;
	}
	reg[1] = addr << 1;

	/* Select the DF memory to check. */
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);

	/* Send the Manufacturer ID Read command. */
	usart_spi_write_packet(USART_SPI, reg, 2);

	/* Receive Manufacturer ID. */
	usart_spi_read_packet(USART_SPI, reg, 1);
	
	/* Deselect the checked DF memory. */
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	
	return reg[0];
}

/*
*	Write to the switch registers
*
* SPI write cycle
*      |         reg[0]        |         reg[1]        |         reg[2]        |
* S_DI | 0  1  0 __ __ __ __ A7 A6 A5 A4 A3 A2 A1 A0 TR D7 D6 D5 D4 D3 D2 D1 D0
*/
void switch_write(uint8_t addr, uint8_t value)
{
	uint8_t reg[3];
	if (addr < 128) {
		reg[0] = 64;
	} else {
		reg[0] = 65;
	}
	reg[1] = addr << 1;
	reg[2] = value;
	
	/* Select the DF memory to check. */
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);

	/* Send the Manufacturer ID Read command. */
	usart_spi_write_packet(USART_SPI, reg, 3);
	
	/* Deselect the checked DF memory. */
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
}

static void switch_unreach(void){
	volatile uint32_t noop = 0;
	while(1){ noop++; }
}

extern bool disable_ofp_pipeline;
/*
*	Disable OpenFlow functionality
*
*/
void disableOF(void)
{
	disable_ofp_pipeline = true;
}

/*
*	Enable OpenFlow functionality
*
*/
void enableOF(void)
{
	disable_ofp_pipeline = false;
}

/*
*	GMAC write function
*	
*	@param *p_buffer - pointer to the buffer containing the data to send.
*	@param ul_size - size of the data.
*	@param port - the port to send the data out from.
*
*/
void gmac_write(const void *buffer, uint16_t ul_size, uint8_t port){
	if(port==0x80){ // special rule here. don't send to openflow port
		uint8_t n = 0;
		for(int i=0; i<MAX_PORTS; i++){
			if(Zodiac_Config.of_port[i] != 1){
				n |= 1<<i;
			}
		}
		port = n;
	}
	// switch discards frames less than 64 bytes (ethernet minimum size)
	uint8_t tx_buffer[GMAC_FRAME_LENTGH_MAX];
	uint32_t tx_buffer_length;
	if (ul_size < 60){ // Add padding to 60 bytes (60 + 4(FCS)==64)
		tx_buffer_length = 60;
		memset(tx_buffer, 0, 61);
	} else if (ul_size < GMAC_FRAME_LENTGH_MAX) {
		tx_buffer_length = ul_size;
	} else {
		return;
	}
	memcpy(tx_buffer, buffer, ul_size);
	uint8_t *last_byte = (void*)((uintptr_t)tx_buffer + tx_buffer_length);
	*last_byte = port;
	gmac_dev_write(&gs_gmac_dev, tx_buffer, tx_buffer_length+1, NULL);
	return;
}

/*
*	GMAC handler function
*
*/
void GMAC_Handler(void)
{
	gmac_handler(&gs_gmac_dev);
}

#define SWITCH_CONFIG_MASK (OFPPC_NO_FWD|OFPPC_NO_RECV|OFPPC_PORT_DOWN);
uint32_t get_switch_config(uint32_t port){
	uint32_t ret = 0;
	if(port>=4){
		return ret;
	}
	static uint8_t fwd[] = {18, 34, 50, 66};
	static uint8_t pwr[] = {29, 45, 61, 77};
	uint8_t r = switch_read(fwd[port]);
	if((r & 0x04) == 0){
		ret |= OFPPC_NO_FWD;
	}
	if((r & 0x02) == 0){
		ret |= OFPPC_NO_RECV;
	}
	r = switch_read(pwr[port]);
	if((r & 0x08) == 1){
		ret |= OFPPC_PORT_DOWN;
	}
	return ret;
}

#define SWITCH_STATUS_MASK OFPPS10_LINK_DOWN;
uint32_t get_switch_status(uint32_t port){
	uint32_t ret = 0;
	if(port >= 4){
		return ret;
	}
	static uint8_t status2[] = {30, 46, 62, 78};
	uint8_t r = switch_read(status2[port]);
	if((r & 0x20) == 0){
		ret |= OFPPS13_LINK_DOWN;
	}
	return ret;
}

uint32_t get_switch_ofppf13_curr(uint32_t port){
	uint32_t ret = 0;
	if(port >= 4){
		return ret;
	}
	ret |= OFPPF13_COPPER;
	static const uint8_t status1[] = {25,41,57,73};
	uint8_t r = switch_read(status1[port]);
	static const uint32_t idx[] = {
		OFPPF13_10MB_HD,
		OFPPF13_10MB_FD,
		OFPPF13_100MB_HD,
		OFPPF13_100MB_FD,
	};
	ret |= idx[(r>>1)&0x3];
	return ret;
}

uint32_t get_switch_ofppf13_advertised(uint32_t port){
	uint32_t ret = 0;
	if(port >= 4){
		return ret;
	}
	ret |= OFPPF13_COPPER;
	
	static const uint8_t ctl7[] = {23, 39, 55, 71};
	uint8_t r = switch_read(ctl7[port]);
	if((r & 0x30)==0x10){
		ret |= OFPPF13_PAUSE;
	}
	if((r & 0x30)==0x20){
		ret |= OFPPF13_PAUSE_ASYM;
	}
	if((r & 0x08) != 0){
		ret |= OFPPF13_100MB_FD;
	}
	if((r & 0x04) != 0){
		ret |= OFPPF13_100MB_HD;
	}
	if((r & 0x02) != 0){
		ret |= OFPPF13_10MB_FD;
	}
	if((r & 0x01) != 0){
		ret |= OFPPF13_10MB_HD;
	}
	static const uint8_t ctl9[] = {28,44,60,76};
	r = switch_read(ctl9[port]);
	if((r & 0x80) == 0){
		ret |= OFPPF13_AUTONEG;
	}
	return ret;
}

uint32_t get_switch_ofppf13_peer(uint32_t port){
	uint32_t ret = 0;
	if(port >= 4){
		return ret;
	}
	ret |= OFPPF13_COPPER;
	
	static const uint8_t status0[] = {24,40,56,72};
	uint8_t r = switch_read(status0[port]);
	if((r & 0x30)==0x10){
		ret |= OFPPF13_PAUSE;
	}
	if((r & 0x30)==0x20){
		ret |= OFPPF13_PAUSE_ASYM;
	}
	if((r & 0x08) != 0){
		ret |= OFPPF13_100MB_FD;
	}
	if((r & 0x04) != 0){
		ret |= OFPPF13_100MB_HD;
	}
	if((r & 0x02) != 0){
		ret |= OFPPF13_10MB_FD;
	}
	if((r & 0x01) != 0){
		ret |= OFPPF13_10MB_HD;
	}
	return ret;
}

extern struct fx_port_count fx_port_counts[4];
void sync_switch_port_counts(uint8_t port_index){
	uint8_t txreg[4];
	uint8_t rxreg[5];
	
	// switch_write(110, 0x1d); // write, MIB, 0x1??
	// switch_write(111, 4*port_index); // 0x100, 0x104, ... indirect address
	//fx_port_counts[port_index].rx_bytes += (
	//((switch_read(116) & 0x0f)<<32)
	//+ (switch_read(117)<<24)
	//+ (switch_read(118)<<16)
	//+ (switch_read(119)<<8)
	//+ switch_read(120));
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1d;
	txreg[3] = 4*port_index;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 116, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 5);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	fx_port_counts[port_index].rx_bytes += (((uint64_t)rxreg[0] & 0x0f)<<32);
	fx_port_counts[port_index].rx_bytes += htonl(*(uint32_t*)((uintptr_t)rxreg+1));
	
	//switch_write(110, 0x1d);
	//switch_write(111, 4*port_index + 1);
	//fx_port_counts[port_index].tx_bytes += (
		//((switch_read(116) & 0x0f)<<32)
		//+ (switch_read(117)<<24)
		//+ (switch_read(118)<<16)
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1d;
	txreg[3] = 4*port_index + 1;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 116, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 5);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	fx_port_counts[port_index].tx_bytes += (((uint64_t)rxreg[0] & 0x0f)<<32);
	fx_port_counts[port_index].tx_bytes += htonl(*(uint32_t*)((uintptr_t)rxreg+1));

	//switch_write(110, 0x1d);
	//switch_write(111, 4*port_index + 2);
	//fx_port_counts[port_index].rx_dropped += (
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1d;
	txreg[3] = 4*port_index + 2;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 119, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 2);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	fx_port_counts[port_index].rx_dropped += ntohs(*(uint16_t*)(uintptr_t)rxreg);

	//switch_write(110, 0x1d);
	//switch_write(111, 4*port_index + 3);
	//fx_port_counts[port_index].tx_dropped += (
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1d;
	txreg[3] = 4*port_index + 3;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 119, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 2);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	fx_port_counts[port_index].tx_dropped += ntohs(*(uint16_t*)(uintptr_t)rxreg);

	uint64_t rx_err_sum = 0;
	uint64_t rx_err = 0;
	
	//switch_write(110, 0x1c);
	//switch_write(111, 0x7 + 0x20*port_index);
	//rx_err = (((switch_read(117) & 0x1f)<<24)
		//+ (switch_read(118)<<16)
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	//fx_port_counts[port_index].rx_frame_err += rx_err;
	//rx_err_sum += rx_err;
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1c;
	txreg[3] = 0x7 + 0x20*port_index;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 117, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	rx_err = ntohl(*(uint32_t*)(uintptr_t)rxreg) & 0x1fffffff;
	fx_port_counts[port_index].rx_frame_err += rx_err;
	rx_err_sum += rx_err;
	
	//switch_write(110, 0x1c);
	//switch_write(111, 0x3 + 0x20*port_index);
	//rx_err = (((switch_read(117) & 0x1f)<<24)
		//+ (switch_read(118)<<16)
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	//fx_port_counts[port_index].rx_over_err += rx_err;
	//rx_err_sum += rx_err;
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1c;
	txreg[3] = 0x3 + 0x20*port_index;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 117, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	rx_err = ntohl(*(uint32_t*)(uintptr_t)rxreg) & 0x1fffffff;
	fx_port_counts[port_index].rx_over_err += rx_err;
	rx_err_sum += rx_err;
	
	//switch_write(110, 0x1c);
	//switch_write(111, 0x6 + 0x20*port_index);
	//rx_err = (((switch_read(117) & 0x1f)<<24)
		//+ (switch_read(118)<<16)
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	//fx_port_counts[port_index].rx_crc_err += rx_err;
	//rx_err_sum += rx_err;
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1c;
	txreg[3] = 0x6 + 0x20*port_index;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 117, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	rx_err = ntohl(*(uint32_t*)(uintptr_t)rxreg) & 0x1fffffff;
	fx_port_counts[port_index].rx_crc_err += rx_err;
	rx_err_sum += rx_err;
	
	fx_port_counts[port_index].rx_errors += rx_err_sum;
	
	//switch_write(110, 0x1c);
	//switch_write(111, 0x1c + 0x20*port_index);
		//rx_err = (((switch_read(117) & 0x1f)<<24)
		//+ (switch_read(118)<<16)
		//+ (switch_read(119)<<8)
		//+ switch_read(120));
	//fx_port_counts[port_index].collisions += rx_err;
	encode_spi_reg01(false, 110, txreg);
	txreg[2] = 0x1c;
	txreg[3] = 0x1c + 0x20*port_index;
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	encode_spi_reg01(true, 117, txreg);
	usart_spi_select_device(USART_SPI, &USART_SPI_DEVICE);
	usart_spi_write_packet(USART_SPI, txreg, 2);
	usart_spi_read_packet(USART_SPI, rxreg, 4);
	usart_spi_deselect_device(USART_SPI, &USART_SPI_DEVICE);
	fx_port_counts[port_index].collisions += ntohl(*(uint32_t*)(uintptr_t)rxreg) & 0x1fffffff;
}

void switch_init(){
	/* Wait for PHY to be ready (CAT811: Max400ms) */
	volatile uint32_t ul_delay = sysclk_get_cpu_hz() / 1000 / 3 * 400;
	while (ul_delay--);
	
	/* Enable GMAC clock */
	pmc_enable_periph_clk(ID_GMAC);

	/* Fill in GMAC options */
	NVIC_DisableIRQ(GMAC_IRQn); // we'll setup gmac handler object
	gmac_options_t gmac_option = {
		.uc_copy_all_frame = 1,
		.uc_no_boardcast = 0,
		.uc_mac_addr = {
			Zodiac_Config.MAC_address[0],
			Zodiac_Config.MAC_address[1],
			Zodiac_Config.MAC_address[2],
			Zodiac_Config.MAC_address[3],
			Zodiac_Config.MAC_address[4],
			Zodiac_Config.MAC_address[5],
		},
	};
	/* Init GMAC driver structure */
	gmac_dev_init(GMAC, &gs_gmac_dev, &gmac_option);
	// soft reset
	switch_write(2, 0x76);
	switch_write(31, 0x11);
	switch_write(47, 0x11);
	switch_write(63, 0x11);
	switch_write(79, 0x11);
	/* Init KSZ8795 registers */
	switch_write(86,232);	// Set CPU interface to MII
	switch_write(12, 0x46);	// Turn on tail tag mode
	// CPU(port5) controls the traffic
	switch_write(21, 0x03);
	switch_write(37, 0x03);
	switch_write(53, 0x03);
	switch_write(69, 0x03);
	// port vlan
	switch_write(17, 0x11);
	switch_write(33, 0x12);
	switch_write(49, 0x14);
	switch_write(65, 0x18);
	switch_write(81, 0x1F);
	// disable learning
	switch_write(18, 0x07);
	switch_write(34, 0x07);
	switch_write(50, 0x07);
	switch_write(66, 0x07);
	switch_write(82, 0x07);
	// flush
	switch_write(2, 0x36);
	
	/* Enable Interrupt */
	NVIC_EnableIRQ(GMAC_IRQn);
	
	/* Init MAC PHY driver */
	if(GMAC_OK != ethernet_phy_init(GMAC, BOARD_GMAC_PHY_ADDR, sysclk_get_cpu_hz())){
		// unreach
		return;
	}
	if(GMAC_OK != ethernet_phy_set_link(GMAC, BOARD_GMAC_PHY_ADDR, 1)){
		// unreach
		return;
	}
}

void switch_task(struct netif *netif){
	uint8_t rx_buffer[GMAC_FRAME_LENTGH_MAX];
	uint32_t rx_buffer_length = GMAC_FRAME_LENTGH_MAX;
	// XXX: gmac_dev_read as gmac_low_level_input, may return pbuf chain directly here.
	// XXX: lwip expects frame header structures are all placed in the pbuf first chunk.
	// XXX: and openflow pipeline will expect this as well.
	if (GMAC_OK == gmac_dev_read(&gs_gmac_dev, rx_buffer, GMAC_FRAME_LENTGH_MAX, &rx_buffer_length)){
		// switch is configured to work in tail tag mode
		rx_buffer_length--;
		uint8_t tag = rx_buffer[rx_buffer_length];
		if(tag<4 && Zodiac_Config.of_port[tag]==1){ // XXX: port number hardcoded here
			if(disable_ofp_pipeline == false){
				struct fx_packet frame = {
					.length = rx_buffer_length,
					.capacity = GMAC_FRAME_LENTGH_MAX,
					.data = rx_buffer,
					.in_port = htonl(tag+1),
				};
				fx_port_counts[tag].rx_packets++;
				openflow_pipeline(&frame);
			}
		} else{
			// PBUF_ROM or PBUF_REF fails with ICMP handling: not yet implemented in LWIP.
			struct pbuf *frame = pbuf_alloc(PBUF_RAW, rx_buffer_length, PBUF_POOL);
			if(frame!=NULL){
				pbuf_take(frame, rx_buffer, rx_buffer_length);
				netif->input(frame, netif);
				pbuf_free(frame);
			}else{
				switch_unreach();
			}
		}
	}
	return;
}
