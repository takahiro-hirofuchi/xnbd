# Copyright (C) 2008-2009 National Institute of Advanced Industrial Science and Technology
# 
# Author: Takahiro Hirofuchi
#



CC=gcc
CFLAGS=-g -O2 -Wall -fstack-protector -fstack-check -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` 
SRC=common.c net.c io.c bitmap.c nbd.c
OBJ=$(SRC:%.c=%.o)

obj_dbg=$(patsubst %.c, %___dbg.o, $(SRC))


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%___dbg.o: %.c
	$(CC) $(CFLAGS) -DXNBD_DEBUG -c $< -o $@

%.d: %.c
	$(CC) -MM $(CFLAGS) $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@

all: libxutils.a libxutils_dbg.a

libxutils.a: $(OBJ)
	ar crsv $@ $^

libxutils_dbg.a: $(obj_dbg)
	ar crsv $@ $^

.PHONY: all clean 
clean:
	rm -rf *.o *.d *.a

-include $(patsubst %.c, %.d, $(SRC))
