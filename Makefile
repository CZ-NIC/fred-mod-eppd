APXS=/home/loo/apache.org/chroot/bin/apxs
INC=/home/loo/apache.org/chroot/include

.PHONY: clean build install

build: mod_eppd.c
	$(APXS) -c mod_eppd.c

install: mod_eppd.c
	$(APXS) -c -i mod_eppd.c

clean:
	rm -f mod_eppd.loT
	rm -f mod_eppd.la
	rm -f mod_eppd.lo
	rm -f mod_eppd.o
	rm -f mod_eppd.slo
	rm -rf .libs
