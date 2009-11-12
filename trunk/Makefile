# Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
#



CC=gcc
# -O3 makes a broken binary.
CFLAGS_COMMON=-g -O2 -Wall -fstack-protector -fstack-check -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0`
XUTILSPATH=./lib
CFLAGS=$(CFLAGS_COMMON) -I$(XUTILSPATH) -L$(XUTILSPATH) -lxutils
CFLAGS_DEBUG=$(CFLAGS_COMMON) -I$(XUTILSPATH) -L$(XUTILSPATH) -lxutils_dbg -DXNBD_DEBUG

#CFLAGS_CHECKING=-O2 -Wall -fstack-protector -fstack-check -fmudflapth -lmudflapth -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` 
#CFLAGS_CHECKING=-O2 -Wall -Wextra -std=gnu99 -fmudflapth -lmudflapth  `pkg-config --cflags --libs glib-2.0 gthread-2.0` 
CFLAGS_CHECKING=-O2 -Wall -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` 

#CFLAGS=-g3 -fstack-protector -fmudflapth -lmudflapth -Wall -Wextra -std=gnu99

SRC=xnbd.c xnbd_common.c xnbd_cachestat.c xnbd_proxy.c xnbd_target.c
OBJ=$(SRC:%.c=%.o)

xnbdobj_dbg=$(patsubst %.c, %___dbg.o, $(SRC))


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%___dbg.o: %.c
	$(CC) $(CFLAGS_DEBUG) -c $< -o $@

%.d: %.c
	$(CC) -MM $(CFLAGS) $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@

%__dbg.d: %.c
	$(CC) -MM $(CFLAGS_DEBUG) $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@


default: xnbd-server xnbd-bgctl

# 1. Put $(OBJ) before $(CFLAGS). To avoid undefined reference error, object
# files must be followed by static libraries to be linked with them.
#
# 2. Do make -C $(XUTILSPATH). This makes sure static libraries are always
# up-to-date for their source files. The dependency files created by gcc -MM do
# not cover the dependency related to *.c of libraries; only cover header
# files.
xnbd-server: $(OBJ)
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-server 

xnbd-server-debug: $(xnbdobj_dbg)
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS_DEBUG) -o xnbd-server-debug

xnbd-server-test: $(xnbdobj_dbg)
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS_CHECKING) -DXNBD_STATIC_BGCTL -o xnbd-server-test

xnbd-server-cachestat: $(OBJ)
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -DCACHESTAT_ENABLED -o xnbd-server-cachestat

xnbd-cachestatdump: xnbd_cachestatdump.c $(filter-out xnbd.o, $(OBJ))
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-cachestatdump

xnbd-tester: xnbd_tester.c $(filter-out xnbd.o, $(OBJ))
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-tester

xnbd-bgctl: xnbd_bgctl.c $(filter-out xnbd.o, $(OBJ))
	make -C $(XUTILSPATH)
	$(CC) $^ $(CFLAGS) -o xnbd-bgctl

#$(XUTILSPATH)/libxutils.a: $(wildcard $(XUTILSPATH)/*.c)
#	make -C $(XUTILSPATH) libxutils.a
#
#$(XUTILSPATH)/libxutils_dbg.a:
#	make -C $(XUTILSPATH) libxutils_dbg.a


.PHONY: clean
clean:
	make -C $(XUTILSPATH) clean
	rm -rf *.o *.d xnbd-server xnbd-server-debug xnbd-server-test xnbd-server-cachestat xnbd-cachestatdump xnbd-bgctl xnbd-tester

-include $(patsubst %.c, %.d, $(SRC))
