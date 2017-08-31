#
# Makefile
# Mathias Weidner, 2017-08-12 19:19
#
IMAGES = ipsec-tester-dfd.png

%.png: src/%.ditaa; ditaa $< $@ > /dev/null

all: $(IMAGES)

clean:
	rm $(IMAGES)

# vim:ft=make
