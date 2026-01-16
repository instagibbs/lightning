#! /usr/bin/make

OPENINGD_HEADERS := 				\
	openingd/common.h			\
	openingd/openingd_wiregen.h

DUALOPEND_HEADERS := 				\
	openingd/common.h			\
	openingd/dualopend_wiregen.h

ELTOO_OPENINGD_HEADERS :=			\
	openingd/common.h			\
	openingd/eltoo_openingd_wiregen.h

OPENINGD_SRC := openingd/openingd.c		\
	$(OPENINGD_HEADERS:.h=.c)

DUALOPEND_SRC := openingd/dualopend.c		\
	$(DUALOPEND_HEADERS:.h=.c)

ELTOO_OPENINGD_SRC := openingd/eltoo_openingd.c	\
	$(ELTOO_OPENINGD_HEADERS:.h=.c)

OPENINGD_OBJS := $(OPENINGD_SRC:.c=.o)
$(OPENINGD_OBJS): $(OPENINGD_HEADERS)

DUALOPEND_OBJS := $(DUALOPEND_SRC:.c=.o)
$(DUALOPEND_OBJS): $(DUALOPEND_HEADERS)

ELTOO_OPENINGD_OBJS := $(ELTOO_OPENINGD_SRC:.c=.o)
$(ELTOO_OPENINGD_OBJS): $(ELTOO_OPENINGD_HEADERS)

# Make sure these depend on everything.
ALL_C_SOURCES += $(OPENINGD_SRC) $(DUALOPEND_SRC) $(ELTOO_OPENINGD_SRC)
ALL_C_HEADERS += $(OPENINGD_HEADERS) $(DUALOPEND_HEADERS) $(ELTOO_OPENINGD_HEADERS)
ALL_PROGRAMS += lightningd/lightning_openingd lightningd/lightning_dualopend lightningd/lightning_eltoo_openingd

# Here's what lightningd depends on
LIGHTNINGD_CONTROL_HEADERS += openingd/openingd_wiregen.h openingd/dualopend_wiregen.h openingd/eltoo_openingd_wiregen.h
LIGHTNINGD_CONTROL_OBJS += openingd/openingd_wiregen.o openingd/dualopend_wiregen.o openingd/eltoo_openingd_wiregen.o

lightningd/lightning_openingd: $(OPENINGD_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

lightningd/lightning_dualopend: $(DUALOPEND_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

lightningd/lightning_eltoo_openingd: $(ELTOO_OPENINGD_OBJS) $(HSMD_CLIENT_OBJS) libcommon.a

-include openingd/test/Makefile
