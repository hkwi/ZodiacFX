/**
 * @file
 * timers.c
 *
 * This file contains the timer functions
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
#include <signal.h>
#include "board.h"
#include "tc.h"
#include "timers.h"
#include "lwip/init.h"
#include "lwip/sys.h"

/* Clock tick count. */
static volatile uint32_t gs_ul_clk_tick = 0;

#include "pmc.h"
#include "sysclk.h"

/**
 *	TC0 Interrupt handler.
 *
 */
void TC0_Handler(void)
{
	/* Increase tick. */
	gs_ul_clk_tick++;

	/* Clear status bit to acknowledge interrupt. */
	volatile uint32_t ul_dummy = TC0->TC_CHANNEL[0].TC_SR;
}

/**
 * Initialize the timer counter (TC0).
 *
 */
void sys_init_timing(void)
{
	uint32_t ul_div;
	uint32_t ul_tcclks;
	uint32_t ul_sysclk = sysclk_get_cpu_hz();

	/* Configure PMC. */
	pmc_enable_periph_clk(ID_TC0);

	/* Configure TC for a 1kHz frequency and therefore a 1ms rate */
	tc_find_mck_divisor(1000, ul_sysclk, &ul_div, &ul_tcclks, ul_sysclk);
	tc_init(TC0, 0, ul_tcclks | TC_CMR_CPCTRG);
	tc_write_rc(TC0, 0, (ul_sysclk / ul_div) / 1000);

	/* Configure and enable interrupt on RC compare. */
	NVIC_EnableIRQ((IRQn_Type)ID_TC0);
	tc_enable_interrupt(TC0, 0, TC_IER_CPCS);
	
	/* Start timer. */
	tc_start(TC0, 0);
}

// This must be maintained in tracking the wrap-around
static uint32_t gs_ul_clk_high = 0;

uint64_t sys_get_ms64(void){
	static uint32_t clk = 0;
	if (gs_ul_clk_tick < clk){
		gs_ul_clk_high++;
	}
	clk = gs_ul_clk_tick;
	return ((uint64_t)gs_ul_clk_high<<32) + gs_ul_clk_tick;
}

/**
 * Return the number of timer ticks (ms).
 *
 */
uint32_t sys_get_ms(void)
{
	return gs_ul_clk_tick;
}


#if ((LWIP_VERSION) != ((1U << 24) | (3U << 16) | (2U << 8) | (LWIP_VERSION_RC)))
u32_t sys_now(void)
{
	return (sys_get_ms());
}
#endif
