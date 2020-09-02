#
# Copyright (C) 2019 EMQX, Inc. Jaylin Yu
#

CC = gcc
CFLAGS += -Wall -fno-strict-aliasing -W -std=gnu99
CFLAGS += -I. -Ishared/ -Iconfig/ -Icheckin/ -Iapps/ `pkg-config --cflags `
OFLAGS += -Os
CPPFLAGS="-D PARALLEL=32 -I /usr/local/include"
LDFLAGS2="-L /usr/local/lib -lnng"
CC2="cc"
LDFLAGS += $(OFLAGS) -lrt `pkg-config`

EXTRA_CFLAGS += -DDEBUG_CONSOLE
# EXTRA_CFLAGS += -DDEBUG_FILE
EXTRA_CFLAGS += -DDEBUG_SYSLOG
# EXTRA_CFLAGS += -DDEBUG_TRACE

SRC_C = nanomq.c apps.c cmd.c process.c file.c const_string.c $(wildcard apps/*.c) $(wildcard config/*.c) $(wildcard shared/*.c) $(wildcard checkin/*.c)
SRC_H = ./include/nanomq.h ./include/apps.h $(wildcard apps/*.h) $(wildcard config/*.h) $(wildcard shared/*.h) $(wildcard checkin/*.h) $(wildcard include/*.h)
SRC_O = $(SRC_C:.c=.o)

ifneq ($(CONFIG_REGDBQUERY_STATIC_ONLY), y)
  $(warning Makefile is valid!)
endif

ifeq ($(EMQ_DEBUG), y)
  EXTRA_CFLAGS += -DDEBUG_CONSOLE
  EXTRA_CFLAGS += -DDEBUG_SYSLOG
endif

CFLAGS +=
LDFLAGS += -Wl,-Bstatic -Wl,-Bdynamic

nanomq: $(SRC_O) $(SRC_H) Makefile
	$(CC) -o $@ $(SRC_O) $(LDFLAGS)
	

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) -MD -c $< -o $@

clean:
	rm -f nanomq *.o *~ apps/*.o apps/*~ config/*.o config/*~ shared/*.o shared/*~
	rm -f `find . -name '*.d' -print`
