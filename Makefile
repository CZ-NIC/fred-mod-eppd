APXS	= apxs
APR-CONFIG	= apr-config
ORBIT2-CONFIG	= orbit2-config
ORBIT-IDL-2	= orbit-idl-2
PKG-CONFIG	= pkg-config

IDLOUT	= ccReg.h ccReg-common.c ccReg-stubs.c
OBJS	= mod_eppd.o epp_xml.o epp-client.o ccReg-common.o ccReg-stubs.o
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

CFLAGS	= -DNDEBUG -g -O0 -fPIC -Wall
LDFLAGS	= -rpath $(AP_INSTALLDIR) -Bshareable

build: mod_eppd.so

install: mod_eppd.so
	cp -f mod_eppd.so $(AP_INSTALLDIR)

mod_eppd.so: $(OBJS)
	ld -o mod_eppd.so $(LDFLAGS) $(AP_LDFLAGS) $(ORB_LDFLAGS) $(OBJS) $(AP_LIBS) $(XML_LIBS)

mod_eppd.o:	mod_eppd.c epp_xml.h epp_common.h epp-client.h
	gcc $(CFLAGS) $(AP_CFLAGS) $(AP_INCLUDE) -c mod_eppd.c

epp_xml.o: epp_xml.c epp_xml.h epp_common.h
	gcc $(CFLAGS) $(XML_CFLAGS) -c epp_xml.c

epp-client.o: epp-client.c epp-client.h epp_common.h ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c epp-client.c

ccReg-common.o: ccReg-common.c ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-common.c

ccReg-stubs.o: ccReg-stubs.c ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-stubs.c

test: test.o epp_xml.o epp-client.o ccReg-common.o ccReg-stubs.o
	gcc -o test -g -Wall $(ORB_LDFLAGS) test.o epp_xml.o epp-client.o ccReg-common.o ccReg-stubs.o $(XML_LIBS)

test.o: test.c epp_common.h epp_xml.h epp-client.h
	gcc -c -g -O0 -Wall -c test.c

$(IDLOUT): $(IDL)
	$(ORBIT-IDL-2) --noskels $(IDL)

clean:
	-rm -f $(OBJS)
	-rm -f $(IDLOUT)
	-rm -f test test.o
	-rm -f 

distclean: clean
	-rm -f mod_eppd.so


.PHONY: clean distclean install build

