ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib doc .


sbin_PROGRAMS = \
	xnbd-server \
	xnbd-bgctl \
	xnbd-client \
	xnbd-watchdog \
	xnbd-wrapper

noinst_PROGRAMS = \
	xnbd-cachestatdump \
	xnbd-tester

lib_LTLIBRARIES = \
	libxnbd_internal.la

dist_sbin_SCRIPTS = \
	xnbd-register.py \
	xnbd-wrapper-ctl.py


libxnbd_internal_la_SOURCES = \
	xnbd.h \
	xnbd_cachestat.c \
	xnbd_common.c \
	xnbd_common.h \
	xnbd_proxy.c \
	xnbd_proxy.h \
	xnbd_proxy_forwarder.c \
	xnbd_target_cow_lzo.c
libxnbd_internal_la_LIBADD = lib/libxutils.la


xnbd_server_LDADD = libxnbd_internal.la
xnbd_server_SOURCES = \
	xnbd_server.c \
	xnbd_target.c


xnbd_bgctl_LDADD = libxnbd_internal.la
xnbd_bgctl_SOURCES = xnbd_bgctl.c


xnbd_client_LDADD = libxnbd_internal.la
xnbd_client_SOURCES = xnbd_client.c


xnbd_watchdog_LDADD = libxnbd_internal.la
xnbd_watchdog_SOURCES = xnbd_watchdog.c


xnbd_wrapper_LDADD = libxnbd_internal.la
xnbd_wrapper_SOURCES = xnbd_wrapper.c


xnbd_cachestatdump_LDADD = libxnbd_internal.la
xnbd_cachestatdump_SOURCES = xnbd_cachestatdump.c


xnbd_tester_LDADD = libxnbd_internal.la
xnbd_tester_SOURCES = xnbd_tester.c


dist_sysconf_DATA = xnbd.conf

# Install change log and read me, too
dist_doc_DATA = \
	ChangeLog \
	README


AM_CPPFLAGS = @GLIB_CFLAGS@
AM_LDFLAGS = @GLIB_LIBS@


install-exec-hook:
	mv $(DESTDIR)$(sbindir)/xnbd-register{.py,}
	mv $(DESTDIR)$(sbindir)/xnbd-wrapper-ctl{.py,}

uninstall-hook:
	rm $(DESTDIR)$(sbindir)/xnbd-wrapper-ctl
	rm $(DESTDIR)$(sbindir)/xnbd-register


# Target added for backwards-compatibility with previous Makefile
.PHONY: manpages
manpages:
	$(MAKE) -C doc
