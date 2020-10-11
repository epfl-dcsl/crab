ROOTDIR=$(shell git rev-parse --show-toplevel)
RTE_SDK=$(ROOTDIR)/middlebox/dpdk/r2p2/dpdk
R2P2LIB_DIR=$(ROOTDIR)/middlebox/dpdk/r2p2/r2p2

include $(ROOTDIR)/middlebox/dpdk/r2p2/netstack/dp/dir.mk
include $(ROOTDIR)/middlebox/dpdk/r2p2/netstack/net/dir.mk
include $(R2P2LIB_DIR)/dir.mk


CC=gcc
CFLAGS += -g -O2 -I$(ROOTDIR)/middlebox/dpdk/r2p2/netstack/inc -I$(R2P2LIB_DIR)/inc -I$(RTE_SDK)/x86_64-native-linuxapp-gcc/include -DNO_BATCH

WERROR_FLAGS := -W -Wall -Wstrict-prototypes -Wmissing-prototypes
WERROR_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
WERROR_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual
WERROR_FLAGS += -Wformat-nonliteral -Wformat-security
WERROR_FLAGS += -Wundef -Wwrite-strings

CFLAGS += $(WERROR_FLAGS) -mavx2
LDFLAGS= -Wl,--whole-archive -Wl,-ldpdk -Wl,--no-whole-archive -lrt -lpthread -lm -ldl -L$(RTE_SDK)/x86_64-native-linuxapp-gcc/lib -lconfig -lnuma -lgcov --coverage -lpcap

SRCS_C := $(addprefix $(ROOTDIR)/middlebox/dpdk/r2p2/netstack/dp/, $(DP_SRC)) $(addprefix $(ROOTDIR)/middlebox/dpdk/r2p2/netstack/net/, $(NET_SRC)) $(addprefix $(R2P2LIB_DIR)/, $(R2P2_SRC_C))
OBJS_C := $(patsubst %.c, %.o, $(SRCS_C))

all: crab lbl4-vanilla

lbl4-vanilla: CFLAGS += -DLBL4_VANILLA -DROUTER
lbl4-vanilla: cleanstate lbl4-vanilla.o $(OBJS_C)
	$(CC) -o $@ lbl4-vanilla.o $(OBJS_C) $(LDFLAGS)

crab: CFLAGS += -DLBL4 -DROUTER
crab: cleanstate crab.o $(OBJS_C)
	$(CC) -o $@ crab.o $(OBJS_C) $(LDFLAGS)

cleanstate:
	make -C $(R2P2LIB_DIR) clean
	make clean
	rm -f $(ROOTDIR)/netstack/net/*.o
	rm -f $(ROOTDIR)/netstack/dp/*.o

clean:
	rm -f *.o

distclean:
	make clean
	rm -f lbl4 lbl4-vanilla
