# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2016-2017 Intel Corporation
# Copyright(c) 2020 Mellanox Technologies

include $(RTE_SDK)/mk/rte.vars.mk


APP = hra_lite
#APP = hra

CFLAGS += $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -g
CFLAGS += -DDPDK
CFLAGS += -Wno-discarded-qualifiers
#CFLAGS += -O3 -g

# all source are stored in SRCS-y
SRCS-y += hra_lite_main.c
#SRCS-y += hra_main.c
SRCS-y += hra_platform.c
SRCS-y += hra_jobset.c
SRCS-y += hra_log_files.c
SRCS-y += hra_jar_table.c
SRCS-y += rxp-api.c

LDLIBS += -lrte_regexdev

include $(RTE_SDK)/mk/rte.app.mk
