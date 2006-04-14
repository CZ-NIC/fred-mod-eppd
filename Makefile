APXS	= apxs
APR-CONFIG	= apr-config
ORBIT2-CONFIG	= orbit2-config
ORBIT-IDL-2	= orbit-idl-2
PKG-CONFIG	= pkg-config

IDLOUT	= ccReg.h ccReg-common.c ccReg-stubs.c
OBJS	= mod_eppd.o epp_parser.o epp-client.o ccReg-common.o ccReg-stubs.o
IDL	= ../cr/idl/ccReg.idl

ORB_LDFLAGS	= $(shell $(ORBIT2-CONFIG) --libs | sed -e s/-Wl,//g -e s/-pthread/-lpthread/g)
ORB_CFLAGS	= $(shell $(ORBIT2-CONFIG) --cflags)

XML_CFLAGS   =$(shell $(PKG-CONFIG) --cflags libxml-2.0)
XML_LIBS     =$(shell $(PKG-CONFIG) --libs libxml-2.0)

AP_CFLAGS	 =$(shell $(APXS) -q CFLAGS)
AP_CFLAGS	+=$(shell $(APXS) -q CFLAGS_SHLIB)
AP_CFLAGS	+=$(shell $(APR-CONFIG) --cppflags)
AP_CFLAGS	+=$(shell $(APR-CONFIG) --cflags)
AP_INCLUDE	 =-I$(shell $(APXS) -q INCLUDEDIR)
AP_INCLUDE	+=$(shell $(APR-CONFIG) --includes)

AP_LDFLAGS	 =$(shell $(APXS) -q LDFLAGS_SHLIB)
AP_LDFLAGS	+=$(shell $(APR-CONFIG) --ldflags)
AP_LIBS	+=$(shell $(APR-CONFIG) --libs)

AP_INSTALLDIR	= $(shell $(APXS) -q LIBEXECDIR)

CFLAGS	= -g -O -fPIC -Wall
LDFLAGS	= -rpath $(AP_INSTALLDIR) -Bshareable

build: mod_eppd.so

install: mod_eppd.so
	cp -f mod_eppd.so $(AP_INSTALLDIR)

mod_eppd.so: $(OBJS)
	ld -o mod_eppd.so $(LDFLAGS) $(AP_LDFLAGS) $(ORB_LDFLAGS) $(OBJS) $(AP_LIBS) $(XML_LIBS)

mod_eppd.o:	mod_eppd.c epp_parser.h
	gcc $(CFLAGS) $(AP_CFLAGS) $(AP_INCLUDE) -c mod_eppd.c

epp_parser.o: epp_parser.c epp_parser.h epp-client.h
	gcc $(CFLAGS) $(XML_CFLAGS) -c epp_parser.c

epp-client.o: epp-client.c epp-client.h ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c epp-client.c

ccReg-common.o: ccReg-common.c
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-common.c

ccReg-stubs.o: ccReg-stubs.c
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-stubs.c

test_parser: test_parser.o epp_parser.o epp-client.o
	gcc -o test_parser $(AP_LDFLAGS) $(ORB_LDFLAGS) test_parser.o epp_parser.o epp-client.o $(XML_LIBS)

test_parser.o: test_parser.c
	gcc -c -g -O0 -Wall -c test_parser.c

$(IDLOUT):
	$(ORBIT-IDL-2) --noskels $(IDL)

clean:
	-rm -f $(OBJS)
	-rm -f $(IDLOUT)
	-rm -f test_parser test_parser.o
	-rm -f 

distclean: clean
	-rm -f mod_eppd.so


.PHONY: clean distclean install build

