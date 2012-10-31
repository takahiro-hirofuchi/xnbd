# 
# xNBD - an enhanced Network Block Device program
# 
# Copyright (C) 2008-2012 National Institute of Advanced Industrial Science
# and Technology
# 
# Author: Takahiro Hirofuchi <t.hirofuchi _at_ aist.go.jp>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
# 
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307, USA.



COMMON_BUILD_FLAGS	?=  -g -O2 -Wall -fstack-protector -fstack-check -Wextra -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0`
DEFAULT_BUILD_FLAGS	= $(COMMON_BUILD_FLAGS)
DEBUG_BUILD_FLAGS	= $(COMMON_BUILD_FLAGS)
SRC			:= $(wildcard *.c)
OBJ			:= $(SRC:%.c=%.o)
OBJ_DBG			:= $(patsubst %.c, %___dbg.o, $(SRC))


all: libxutils.a libxutils_dbg.a

%.o: %.c
	$(COMPILE.c) $(DEFAULT_BUILD_FLAGS) -c $< -o $@

%___dbg.o: %.c
	$(COMPILE.c) $(DEBUG_BUILD_FLAGS) -DXNBD_DEBUG -c $< -o $@

%.d: %.c
	$(COMPILE.c) $(DEFAULT_BUILD_FLAGS) -MM $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@

libxutils.a: $(OBJ)
	$(AR) crsv $@ $^

libxutils_dbg.a: $(OBJ_DBG)
	$(AR) crsv $@ $^

.PHONY: all clean
clean:
	rm -rf *.o *.d *.a libxutils.a libxutils_dbg.a

-include $(patsubst %.c, %.d, $(SRC))
