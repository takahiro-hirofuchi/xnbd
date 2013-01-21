_MANUAL_PACKAGE = @PACKAGE_NAME@
_MANUAL_TITLE = @PACKAGE_NAME@ Manual
_MANUAL_VERSION = @PACKAGE_VERSION@


dist_man1_MANS = \
	xnbd-bgctl.1 \
	xnbd-client.1 \
	xnbd-watchdog.1

dist_man8_MANS = \
	xnbd-server.8 \
	xnbd-wrapper.8 \
	xnbd-wrapper-ctl.8


_RAW_MANPAGES = $(dist_man1_MANS) $(dist_man8_MANS)
_MANPAGE_INPUT = $(patsubst %, %.txt, $(_RAW_MANPAGES))
_HTML_FILES = $(patsubst %, %.html, $(_RAW_MANPAGES))


EXTRA_DIST = $(_MANPAGE_INPUT)

dist_pkgdatadir = @htmldir@
dist_pkgdata_DATA = $(_HTML_FILES)


define TEMPLATE
%.$(section)$(1): %.$(section).txt asciidoc.conf Makefile
	a2x \
		--conf-file=asciidoc.conf \
		--attribute="manual_package=$$(_MANUAL_PACKAGE)" \
		--attribute="manual_title=$$(_MANUAL_TITLE)" \
		--attribute="manual_version=$$(_MANUAL_VERSION)" \
		--format=$(2) -D . \
		"$$<"
endef


_MANPAGE_SECTIONS = $(shell for i in $(_RAW_MANPAGES); do echo $$i ; done | sed 's|.*\.||' | sort -u)
$(foreach section,$(_MANPAGE_SECTIONS),$(eval $(call TEMPLATE,.html,xhtml)))
$(foreach section,$(_MANPAGE_SECTIONS),$(eval $(call TEMPLATE,,manpage)))
