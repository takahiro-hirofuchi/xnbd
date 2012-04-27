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


INSTALL = install
PREFIX ?= $(DESTDIR)/usr/sbin


DOCPATH = ./doc
XUTILSPATH = ./lib

# -O3 $(MAKE)s a broken binary.
COMMON_BUILD_FLAGS	:= -g -O2 -Wall -Wextra -Wstrict-aliasing=2 -Wformat=2 -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith -Wswitch-enum -fstack-protector -fstack-check -std=gnu99 `pkg-config --cflags --libs glib-2.0 gthread-2.0` -I$(XUTILSPATH) -L$(XUTILSPATH)

NEED_GTHREAD_INIT=$(shell pkg-config --atleast-version=2.32.0 glib-2.0 || echo 1)

ifeq ($(NEED_GTHREAD_INIT), 1)
COMMON_BUILD_FLAGS	+= -DNEED_GTHREAD_INIT
endif

DEFAULT_BUILD_FLAGS	:= $(COMMON_BUILD_FLAGS) -lxutils
# -DCACHESTAT_ENABLED does not work.
DEBUG_BUILD_FLAGS	:= $(COMMON_BUILD_FLAGS) -lxutils_dbg -DXNBD_DEBUG

SRC			:= $(wildcard *.c)
# xnbd-cachestatdump is out-of-date.
BINARIES 		:= xnbd-server xnbd-bgctl xnbd-client xnbd-watchdog xnbd-wrapper xnbd-cachestatdump xnbd-tester
BINARIES_OBJ		:= $(subst -,_,$(BINARIES:%=%.o))
OBJ			:= $(SRC:%.c=%.o)

BINARIES_DBG		:= $(BINARIES:%=%-debug)
BINARIES_OBJ_DBG	:= $(BINARIES_OBJ:%.o=%___dbg.o)
OBJ_DBG			:= $(patsubst %.c, %___dbg.o, $(SRC))

.PHONY: all
all: default

%.o: %.c
	$(COMPILE.c) $(DEFAULT_BUILD_FLAGS) -c $< -o $@

%___dbg.o: %.c
	$(COMPILE.c) $(DEBUG_BUILD_FLAGS) -c $< -o $@

%.d: %.c
	$(COMPILE.c) -MM $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@

%__dbg.d: %.c
	$(COMPILE.c) -MM $< -MQ $@ -MQ $(patsubst %.d, %.o, $@) -MF $@


$(XUTILSPATH)/libxutils_dbg.a:
	$(MAKE_COMMAND) -C $(XUTILSPATH) libxutils_dbg.a

$(XUTILSPATH)/libxutils.a:
	$(MAKE_COMMAND) -C $(XUTILSPATH) libxutils.a


$(BINARIES): $(OBJ) $(XUTILSPATH)/libxutils.a
	$(LINK.c) $(subst -,_,$@).o $(filter-out $(BINARIES_OBJ), $^) $(DEFAULT_BUILD_FLAGS) -o $@


$(BINARIES_DBG): $(OBJ_DBG) $(XUTILSPATH)/libxutils_dbg.a
	$(LINK.c) $(subst -,_,$(subst -debug,___dbg,$@).o) $(filter-out	$(BINARIES_OBJ_DBG), $^) $(DEBUG_BUILD_FLAGS) -o $@


.PHONY: default
default: $(BINARIES) manpages

.PHONY: debug
debug: $(BINARIES_DBG)

.PHONY: manpages
manpages:
	$(MAKE_COMMAND) -C $(DOCPATH)

.PHONY: clean install
clean:
	$(MAKE_COMMAND) -C $(XUTILSPATH) clean
	$(MAKE) -C $(DOCPATH) clean
	$(RM) -r *.o *.d $(BINARIES) $(BINARIES_DBG)


install: default
	set -e
	for file in $(filter-out xnbd-cachestatdump xnbd-tester, $(BINARIES)) ; \
	do \
		$(INSTALL) -D --mode=0755 $$file "$(PREFIX)/$$file" ; \
	done
	$(INSTALL) -D --mode=0755 xnbd-wrapper-ctl.py "$(PREFIX)/xnbd-wrapper-ctl"

-include $(patsubst %.c, %.d, $(SRC))
