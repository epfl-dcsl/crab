XDP_TARGETS:= lb_kern

LLC ?= llc
CLANG ?= clang
CC := gcc

include ../common/common.mk

ifeq ($(RAND), 1)
	BPF_CFLAGS += -DRAND
endif
