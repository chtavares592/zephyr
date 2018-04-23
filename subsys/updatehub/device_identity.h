/*
 * Copyright (c) 2016-2017 Linaro Limited
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
   @brief Device Identity implementation for UpudateHub.
 */

#ifndef _DEVICE_IDENTITY_H__
#define _DEVICE_IDENTITY_H__

/**
 * @brief Gets the identity of device
 *
 * @details Gets the device identity sets by device identity init function
 */
char *device_identity_get(void);

/**
 * @brief Initializes the unique identity of the device
 *
 * @details When the UpdateHub starts this function sets the unique device
 * identifier that will be used know that device is updating.
 *
 * @param struct device
 */
void device_identity_init(struct device *dev);

/**
 * @}
 */

#endif /* _DEVICE_IDENTITY_H__ */
