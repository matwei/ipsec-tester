#
# Makefile
# Mathias Weidner, 2017-08-12 19:19
#
%.pdf: %.md; pandoc -o $@ $<

PDFS = README.pdf
SUBDIRS = images

.PHONY: images

all: subdirs

clean:
	rm -f $(PDFS)

images:
	cd images && make

pdf: images $(PDFS)

subdirs: $(SUBDIRS)
	for f in $(SUBDIRS); do cd $$f; make; done

README.pdf: images/ipsec-tester-dfd.png

# vim:ft=make
