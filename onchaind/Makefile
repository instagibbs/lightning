#! /usr/bin/make

ONCHAIND_HEADERS :=				\
	onchaind/onchaind_wiregen.h		\
	onchaind/onchain_types_names_gen.h	\
	onchaind/onchain_types.h		\
	onchaind/onchaind_wire.h

ONCHAIND_SRC := onchaind/onchaind.c	\
	onchaind/onchaind_wiregen.c	\
	onchaind/onchaind_wire.c

ELTOO_ONCHAIND_SRC := onchaind/eltoo_onchaind.c	\
	onchaind/onchaind_wiregen.c	\
	onchaind/onchaind_wire.c

onchaind/onchain_types_names_gen.h: onchaind/onchain_types.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr onchaind/onchain_types.h > $@

ONCHAIND_OBJS := $(ONCHAIND_SRC:.c=.o)
ELTOO_ONCHAIND_OBJS := $(ELTOO_ONCHAIND_SRC:.c=.o)
$(ONCHAIND_OBJS): $(ONCHAIND_HEADERS)
onchaind/eltoo_onchaind.o: $(ONCHAIND_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(ONCHAIND_SRC) onchaind/eltoo_onchaind.c
ALL_C_HEADERS += $(ONCHAIND_HEADERS)
ALL_PROGRAMS += lightningd/lightning_onchaind lightningd/lightning_eltoo_onchaind

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += \
	onchaind/onchaind_wiregen.h \
	onchaind/onchaind_wire.h
LIGHTNINGD_CONTROL_OBJS += \
	onchaind/onchaind_wiregen.o \
	onchaind/onchaind_wire.o

lightningd/lightning_onchaind: $(ONCHAIND_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a
lightningd/lightning_eltoo_onchaind: $(ELTOO_ONCHAIND_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

include onchaind/test/Makefile
