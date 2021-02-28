AUTOMAKE_OPTIONS = foreign subdir-objects

bin_PROGRAMS = itip test_ipsec
itip_SOURCES = src/itip.c \
	       src/sockets.c src/sockets.h \
	       src/ipsec.c src/ipsec.h \
	       src/ipsecsad.c \
	       src/util.c src/util.h
itip_LDADD = -lzlog $(LIBGCRYPT_LIBS) -lgpg-error $(GMODULE_LIBS)
test_ipsec_SOURCES = src/test_ipsec.c \
	       src/sockets.c src/sockets.h \
	       src/ipsec.c src/ipsec.h \
	       src/ipsecsad.c \
	       src/util.c src/util.h
test_ipsec_LDADD = -lzlog $(LIBGCRYPT_LIBS) -lgpg-error $(GMODULE_LIBS)

AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS) $(GMODULE_CFLAGS)
AM_LDFLAGS = $(GMODULE_LIBS)

dist_doc_DATA = README.md \
doc/adr/0001-record-architecture-decisions.md doc/adr/0002-use-libpcap-and-libnet.md doc/adr/0003-only-work-with-configured-vpns.md

%.pdf: %.md; pandoc -o $@ $<

adr.pdf: doc/adr/*.md
	cat doc/adr/*.md | pandoc --toc --toc-depth=1 --include-in-header doc/pandoc/titlesec.tex -o $@

set-capabilities: itip
	sudo setcap cap_net_bind_service=ep itip

