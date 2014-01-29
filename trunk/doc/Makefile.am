# Silent rule support for AsciiDoc
V ?= $(AM_DEFAULT_VERBOSITY)
SILENT_RULE_A2X_MESSAGE_PLAIN  = $(if $(subst 0,,$(V)),@:,@echo "  A2X   " $@)
SILENT_RULE_A2X_MESSAGE_EVALED = $(if $(subst 0,,$(V)),@:,@echo "  A2X   " $$@)
HIDE_A2X = $(if $(subst 0,,$(V)),,@)


_MANUAL_PACKAGE = @PACKAGE_NAME@
_MANUAL_TITLE = @PACKAGE_NAME@ Manual
_MANUAL_VERSION = @PACKAGE_VERSION@


dist_man1_MANS = \
	xnbd-bgctl.1 \
	xnbd-client.1 \
	xnbd-watchdog.1

dist_man8_MANS = \
	xnbd-register.8 \
	xnbd-server.8 \
	xnbd-wrapper.8 \
	xnbd-wrapper-ctl.8


_RAW_MANPAGES = $(dist_man1_MANS) $(dist_man8_MANS)
_MANPAGE_INPUT = $(patsubst %, %.txt, $(_RAW_MANPAGES))
_HTML_FILES = $(patsubst %, %.html, $(_RAW_MANPAGES))

_INCLUDED_FILES = \
	author_toell.txt \
	author_verhelst_toell.txt \
	author_xnbd.txt

EXTRA_DIST = $(_MANPAGE_INPUT) asciidoc.conf $(_INCLUDED_FILES)


dist_html_DATA = $(_HTML_FILES) ChangeLog.html docbook-xsl.css


define TEMPLATE
%.$(section)$(1): %.$(section).txt $(_INCLUDED_FILES) asciidoc.conf Makefile.am ../configure.ac
	@chmod u+w docbook-xsl.css 2>/dev/null || true
	$(SILENT_RULE_A2X_MESSAGE_EVALED)
	$(HIDE_A2X)a2x \
		--conf-file=$$(srcdir)/asciidoc.conf \
		--attribute="manual_package=$$(_MANUAL_PACKAGE)" \
		--attribute="manual_title=$$(_MANUAL_TITLE)" \
		--attribute="manual_version=$$(_MANUAL_VERSION)" \
		--format=$(2) \
		"$$<"
endef

clean-local:
	rm -f $(_RAW_MANPAGES) $(_HTML_FILES) ChangeLog.html docbook-xsl.css


_MANPAGE_SECTIONS = $(shell for i in $(_RAW_MANPAGES); do echo $$i ; done | sed 's|.*\.||' | sort -u)
$(foreach section,$(_MANPAGE_SECTIONS),$(eval $(call TEMPLATE,.html,xhtml)))
$(foreach section,$(_MANPAGE_SECTIONS),$(eval $(call TEMPLATE,,manpage)))


ChangeLog.html docbook-xsl.css: ../ChangeLog asciidoc.conf Makefile.am
	@chmod u+w docbook-xsl.css 2>/dev/null || true
	$(SILENT_RULE_A2X_MESSAGE_PLAIN)
	$(HIDE_A2X)a2x --conf-file=$(srcdir)/asciidoc.conf --format=xhtml -D . "$<"
