# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.
# Copyright(C) 2020 Mellanox International Ltd.
#

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_regexdev.a

EXPORT_MAP := rte_regex_version.map
 
# library version
LIBABIVER := 1

# build flags
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

# library source files
# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_REGEXDEV) := rte_regexdev.c

# export include files
SYMLINK-$(CONFIG_RTE_LIBRTE_REGEXDEV)-include += rte_regexdev.h rte_regexdev_core.h

include $(RTE_SDK)/mk/rte.lib.mk
