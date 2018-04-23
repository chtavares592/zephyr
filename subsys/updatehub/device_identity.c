/*
 * Copyright (c) 2016-2017 Linaro Limited
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <soc.h>

#include "device_identity.h"

/*
 * This is SoC / board specific. The device ID must be unique.
 *
 * DEVICE_ID_BASE: points to the base address of hardware ID registers
 * DEVICE_ID_LENGTH: number or 32-bit words to read
 */

#if defined(CONFIG_SOC_SERIES_NRF52X)
#define DEVICE_ID_BASE          (&NRF_FICR->DEVICEID[0])
#define DEVICE_ID_LENGTH        2
#elif defined(CONFIG_SOC_SERIES_KINETIS_K6X)
#define DEVICE_ID_BASE          (&SIM->UIDH)
#define DEVICE_ID_LENGTH        4
#endif

u32_t device_identity;

char *device_identity_get(void)
{
	char *buffer;

	buffer = k_malloc(DEVICE_ID_LENGTH * 8);

	snprintk(buffer, DEVICE_ID_LENGTH * 8, "%x",
		 device_identity);

	return buffer;
}

#define HASH_MULTIPLIER 37
static u32_t hash32(char *str, int len)
{
	u32_t h = 0;
	int i;

	for (i = 0; i < len; ++i) {
		h = (h * HASH_MULTIPLIER) + str[i];
	}

	return h;
}

void device_identity_init(struct device *dev)
{
	int i;
	char buffer[DEVICE_ID_LENGTH * 8 + 1];

	ARG_UNUSED(dev);

	for (i = 0; i < DEVICE_ID_LENGTH; i++) {
		snprintk(buffer + i * 8, sizeof(buffer) - (i * 8), "%08x",
			 *(((u32_t *)DEVICE_ID_BASE) + i));
	}

	device_identity = hash32(buffer, DEVICE_ID_LENGTH * 8);
}
