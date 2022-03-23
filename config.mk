################################################################################
#
#      Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
#
#            Global configuration Makefile. Included everywhere.
#
################################################################################

ifndef CROSS_CC
CROSS_CC = /opt/xilinx/SDK/2019.1/gnu/aarch32/lin/gcc-arm-none-eabi/bin/arm-none-eabi-gcc
endif
ifdef XILINX_ARM_CC_ROOT
CROSS_CC = ${XILINX_ARM_CC_ROOT}/arm-none-eabi-gcc
endif

ifndef FP
FP = soft
endif

CC :=${CROSS_CC}
CFLAGS += -Os -nostartfiles -fno-short-enums -nostdlib -mcpu=cortex-A9 -mfpu=neon -mfloat-abi=${FP} -mthumb -std=c99 -Wall -Wextra -D_ISOC99_SOURCE -MMD \
	-I../../../../xtratum-base/xcf/xc
#vpath %.c ../lib/source/

# override MinGW built-in recipe
#%.o: %.c
#	$(COMPILE.c) $(OUTPUT_OPTION) $<


export CC
export CFLAGS
#export VPATH

################################################################################
