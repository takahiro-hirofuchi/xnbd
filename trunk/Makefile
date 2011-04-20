#  xNBD - an enhanced Network Block Device program
# 
#  Copyright (C) 2008-2011 National Institute of Advanced Industrial Science
#  and Technology
# 
#  Author: Takahiro Hirofuchi <t.hirofuchi _at_ aist.go.jp>
# 
#  This program is free software; you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by the Free
#  Software Foundation; either version 2 of the License, or (at your option)
#  any later version.
# 
#  This program is distributed in the hope that it will be useful, but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
#  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
#  more details.
# 
#  You should have received a copy of the GNU General Public License along with
#  this program; if not, write to the Free Software Foundation, Inc., 59 Temple
#  Place - Suite 330, Boston, MA 02111-1307, USA.


CC=gcc
INSTALL=install
MAKE=make
RM=rm

# -O3 $(MAKE)s a broken binary.
# CFLAGS_COMMON=-g -O2 -Wall -Wextra -Wstrict-aliasing=2 -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wswitch-enum -Wconversion -fstack-protector -fstack-check -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` -llzo2

CFLAGS_COMMON=-g -O2 -Wall -Wextra -Wstrict-aliasing=2 -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wswitch-enum -Wconversion -fstack-protector -fstack-check -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0`
CFLAGS_COMMON=-g -O2 -Wall -Wextra -Wstrict-aliasing=2 -Wformat=2 -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wswitch-enum -fstack-protector -fstack-check -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0`


#CFLAGS_COMMON=-g -O2 -Wall -Wextra -fstack-check -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` -llzo2 -DXNBD_LZO
#CFLAGS_COMMON=-g -O2 -ftrapv -Wall -Wextra -Wstrict-aliasing=2 -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wswitch-enum -Wconversion -fstack-protector -fstack-check -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` -llzo2
XUTILSPATH=./lib
CFLAGS=$(CFLAGS_COMMON) -I$(XUTILSPATH) -L$(XUTILSPATH) -lxutils
CFLAGS_DEBUG=$(CFLAGS_COMMON) -I$(XUTILSPATH) -L$(XUTILSPATH) -lxutils_dbg -DXNBD_DEBUG

#CFLAGS_CHECKING=-O2 -Wall -fstack-protector -fstack-check -fmudflapth -lmudflapth -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` 
#CFLAGS_CHECKING=-O2 -Wall -Wextra -std=gnu99 -fmudflapth -lmudflapth  `pkg-config --cflags --libs glib-2.0 gthread-2.0` 
#CFLAGS_CHECKING=-O2 -Wall -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` 

#CFLAGS=-g3 -fstack-protector -fmudflapth -lmudflapth -Wall -Wextra -std=gnu99

SRC=xnbd.c xnbd_common.c xnbd_cachestat.c xnbd_proxy.c xnbd_proxy_forwarder.c xnbd_target.c xnbd_target_cow_lzo.c
OBJ=$(SRC:%.c=%.o)

OBJ_DBG=$(patsubst %.c, %___dbg.o, $(SRC))


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%___dbg.o: %.c
	$(CC) $(CFLAGS_DEBUG) -c $< -o $@

%.d: %.c
	$(CC) -MM $(CFLAGS) $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@

%__dbg.d: %.c
	$(CC) -MM $(CFLAGS_DEBUG) $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@


default: xnbd-server xnbd-bgctl xnbd-client xnbd-watchdog xnbd-wrapper

# 1. Put $(OBJ) before $(CFLAGS). To avoid undefined reference error, object
# files must be followed by static libraries to be linked with them.
#
# 2. Do $(MAKE) -C $(XUTILSPATH). This makes sure static libraries are always
# up-to-date for their source files. The dependency files created by gcc -MM do
# not cover the dependency related to *.c of libraries; only cover header
# files.
xnbd-server: $(OBJ)
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-server 

xnbd-server-debug: $(OBJ_DBG)
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS_DEBUG) -o xnbd-server-debug

xnbd-server-cachestat: $(OBJ)
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -DCACHESTAT_ENABLED -o xnbd-server-cachestat

xnbd-cachestatdump: xnbd_cachestatdump.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-cachestatdump

xnbd-tester: xnbd_tester.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-tester

xnbd-tester2: xnbd_tester2.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-tester2

xnbd-bgctl: xnbd_bgctl.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-bgctl

xnbd-bgctl-debug: xnbd_bgctl.c $(filter-out xnbd___dbg.o, $(OBJ_DBG))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS_DEBUG) -o xnbd-bgctl-debug

xnbd-client: xnbd_client.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-client

xnbd-watchdog: xnbd_watchdog.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-watchdog

xnbd-wrapper: xnbd_wrapper.c $(filter-out xnbd.o, $(OBJ))
	$(MAKE) -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-wrapper

.PHONY: manpages
manpages:
	$(MAKE) -C doc

#$(XUTILSPATH)/libxutils.a: $(wildcard $(XUTILSPATH)/*.c)
#	$(MAKE) -C $(XUTILSPATH) libxutils.a
#
#$(XUTILSPATH)/libxutils_dbg.a:
#	$(MAKE) -C $(XUTILSPATH) libxutils_dbg.a


.PHONY: clean install
clean:
	$(MAKE) -C $(XUTILSPATH) clean
	$(MAKE) -C doc clean
	$(RM) -rf *.o *.d xnbd-server xnbd-server-debug xnbd-server-test xnbd-server-cachestat xnbd-cachestatdump xnbd-bgctl xnbd-tester xnbd-client xnbd-watchdog xnbd-wrapper

install: default
	$(INSTALL) -D --mode=0755 xnbd-server $(DESTDIR)/usr/sbin/xnbd-server
	$(INSTALL) -D --mode=0755 xnbd-bgctl  $(DESTDIR)/usr/sbin/xnbd-bgctl
	$(INSTALL) -D --mode=0755 xnbd-client  $(DESTDIR)/usr/bin/xnbd-client
	$(INSTALL) -D --mode=0755 xnbd-watchdog $(DESTDIR)/usr/bin/xnbd-watchdog


-include $(patsubst %.c, %.d, $(SRC))
