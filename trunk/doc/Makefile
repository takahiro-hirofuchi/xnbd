INSTALL ?= install
GZIP 	?= gzip
PREFIX  = $(DESTDIR)/usr/share/

MANUAL_PACKAGE = xNBD
MANUAL_TITLE = xNBD Manual
MANUAL_VERSION = 0.1.0

MANPAGE_SOURCES = $(wildcard *.?.txt)
RAW_MANPAGES = $(patsubst %.txt, %, $(MANPAGE_SOURCES))
COMPRESSED_MANPAGES := $(patsubst %, %.gz, $(RAW_MANPAGES))
HTML_FILES = $(patsubst %.txt, %.html, $(MANPAGE_SOURCES))
MANPAGE_SECTIONS = $(shell for i in $(RAW_MANPAGES); do echo $$i ; done | sed 's|.*\.||')

.PHONY: all
all: $(COMPRESSED_MANPAGES) $(RAW_MANPAGES) $(HTML_FILES)

.PHONY: clean
clean:
	$(RM) $(COMPRESSED_MANPAGES) $(RAW_MANPAGES) $(HTML_FILES)

.PHONY: install
install:


define TEMPLATE
%.$(section)$(1): %.$(section).txt asciidoc.conf Makefile
	a2x \
		--conf-file=asciidoc.conf \
		--attribute="manual_package=$$(MANUAL_PACKAGE)" \
		--attribute="manual_title=$$(MANUAL_TITLE)" \
		--attribute="manual_version=$$(MANUAL_VERSION)" \
		--format=$(2) -D . \
		"$$<"
endef

$(foreach section,$(MANPAGE_SECTIONS),$(eval $(call TEMPLATE,.html,xhtml)))
$(foreach section,$(MANPAGE_SECTIONS),$(eval $(call TEMPLATE,,manpage)))


%.gz: %
	$(GZIP) -c "$<" > "$@"
