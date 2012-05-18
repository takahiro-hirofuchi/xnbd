INSTALL ?= install
GZIP 	?= gzip
PREFIX  = $(DESTDIR)/usr/share/

MANPAGE_SOURCES = $(wildcard *.sgml)
RAW_MANPAGES = $(patsubst %.sgml, %, $(MANPAGE_SOURCES))
COMPRESSED_MANPAGES := $(patsubst %, %.gz, $(RAW_MANPAGES))

.PHONY: all
all: $(COMPRESSED_MANPAGES)

.PHONY: clean
clean:
	$(RM) $(COMPRESSED_MANPAGES) $(RAW_MANPAGES)

.PHONY: install
install:

$(COMPRESSED_MANPAGES): $(MANPAGE_SOURCES)
	docbook-to-man $(patsubst %.gz, %.sgml, $@) > $(patsubst %.gz, %, $@)
	$(GZIP) $(patsubst %.gz, %, $@)
