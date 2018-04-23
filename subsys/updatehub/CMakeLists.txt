#
# Copyright (c) 2018 O.S.Systems
#
# SPDX-License-Identifier: Apache-2.0
#

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_UPDATEHUB device_identity.c)
zephyr_library_sources_ifdef(CONFIG_UPDATEHUB updatehub.c)
