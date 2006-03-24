APXS=/home/loo/apache.org/chroot/bin/apxs
INC=/home/loo/apache.org/chroot/include
CC=gcc
CFLAGS=-g -O0

.PHONY: clean build install

build: mod_eppd.c epp_parser.h epp_parser.o
	$(APXS) -c mod_eppd.c epp_parser.o

install: mod_eppd.c epp_parser.h epp_parser.o
	$(APXS) -c -i mod_eppd.c epp_parser.o

test_parser: test_parser.c epp_parser.h epp_parser.o
	${CC} ${CFLAGS} -o test_parser test_parser.c epp_parser.o

epp_parser.o: epp_parser.c epp_parser.h
	${CC} ${CFLAGS} -c epp_parser.c

clean:
	rm -f mod_eppd.loT
	rm -f mod_eppd.la
	rm -f mod_eppd.lo
	rm -f mod_eppd.o
	rm -f mod_eppd.slo
	rm -f epp_parser.o
	rm -f test_parser
	rm -rf .libs
