INSTALL ?= install
GZIP 	?= gzip
PREFIX  = $(DESTDIR)/usr/share/

MANPAGES := $(patsubst %.sgml, %.gz, $(wildcard *.sgml))

.PHONY: all
all: $(MANPAGES)

.PHONY: clean
clean:
	$(RM) $(MANPAGES)

.PHONY: install
install:

$(MANPAGES):
	docbook-to-man $(patsubst %.gz, %.sgml, $@) | $(GZIP) > $@
