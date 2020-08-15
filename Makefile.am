AUTOMAKE_OPTIONS = foreign subdir-objects

bin_PROGRAMS = itip
itip_SOURCES = src/itip.c \
	       src/sockets.c src/sockets.h \
	       src/ipsec.c src/ipsec.h
itip_LDADD = -lzlog $(LIBGCRYPT_LIBS) -lgpg-error

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS)
AM_LDFLAGS =

dist_doc_DATA = README.md \
doc/adr/0001-record-architecture-decisions.md doc/adr/0002-use-libpcap-and-libnet.md doc/adr/0003-only-work-with-configured-vpns.md

%.pdf: %.md; pandoc -o $@ $<

adr.pdf: doc/adr/*.md
	cat doc/adr/*.md | pandoc --toc --toc-depth=1 --include-in-header doc/pandoc/titlesec.tex -o $@

test-capabilities: $(bin_PROGRAMS)
	sudo setcap cap_net_bind_service=ep $(bin_PROGRAMS)

