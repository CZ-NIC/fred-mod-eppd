#
# Konfigurovatelna cast Makefilu
#
APXS	= apxs
APR-CONFIG	= apr-config
ORBIT-IDL-2	= orbit-idl-2
PKG-CONFIG	= pkg-config
IDL	= ../cr/idl/ccReg.idl
SVN_REV := $(shell svn info | grep Revision | cut -d ' ' -f 2)

#
# Nasledujici cast by nemela vyzadovat zadne zasahy
#
IDLOUT	= ccReg.h ccReg-common.c ccReg-stubs.c
OBJS	= mod_eppd.o epp_common.o epp_xmlcommon.o epp_parser.o epp_gen.o epp-client.o ccReg-common.o ccReg-stubs.o

ORB_LDFLAGS	= $(shell $(PKG-CONFIG) --libs ORBit-2.0)
ORB_CFLAGS	= $(shell $(PKG-CONFIG) --cflags ORBit-2.0)

XML_CFLAGS  =$(shell $(PKG-CONFIG) --cflags libxml-2.0)
XML_LIBS    =$(shell $(PKG-CONFIG) --libs libxml-2.0)

AP_CFLAGS	=$(shell $(APXS) -q CFLAGS)
AP_CFLAGS	+=$(shell $(APXS) -q CFLAGS_SHLIB)
AP_CFLAGS	+=$(shell $(APR-CONFIG) --cppflags)
AP_CFLAGS	+=$(shell $(APR-CONFIG) --cflags)
AP_INCLUDE	=-I$(shell $(APXS) -q INCLUDEDIR)
AP_INCLUDE	+=$(shell $(APR-CONFIG) --includes)

AP_LDFLAGS	=$(shell $(APXS) -q LDFLAGS_SHLIB)
AP_LDFLAGS	+=$(shell $(APR-CONFIG) --ldflags)
AP_LIBS	+=$(shell $(APR-CONFIG) --libs)

AP_INSTALLDIR	:= $(shell $(APXS) -q LIBEXECDIR)

CFLAGS	= -g -O0 -fPIC -Wall
LDFLAGS	= -Wl,-rpath $(AP_INSTALLDIR) -Bshareable

all: build

build: mod_eppd.so

install: mod_eppd.so
	cp -f mod_eppd.so $(AP_INSTALLDIR)

mod_eppd.so: $(OBJS)
	gcc -shared -o mod_eppd.so $(LDFLAGS) $(AP_LDFLAGS) $(ORB_LDFLAGS) $(OBJS) $(AP_LIBS) $(XML_LIBS)

mod_eppd.o:	mod_eppd.c epp_parser.h epp_gen.h epp_common.h epp-client.h
	gcc $(CFLAGS) $(AP_CFLAGS) $(AP_INCLUDE) -D SVN_REV=\"${SVN_REV}\" -c mod_eppd.c

epp_xmlcommon.o: epp_xmlcommon.c epp_xmlcommon.h epp_common.h
	gcc $(CFLAGS) $(XML_CFLAGS) -c epp_xmlcommon.c

epp_parser.o: epp_parser.c epp_parser.h epp_common.h epp_xmlcommon.h
	gcc $(CFLAGS) $(XML_CFLAGS) -c epp_parser.c

epp_gen.o: epp_gen.c epp_gen.h epp_common.h epp_xmlcommon.h epp_version.h
	gcc $(CFLAGS) $(XML_CFLAGS) -c epp_gen.c

epp-client.o: epp-client.c epp-client.h epp_common.h ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c epp-client.c

epp_common.o: epp_common.c epp_common.h
	gcc $(CFLAGS) -c epp_common.c

ccReg-common.o: ccReg-common.c ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-common.c

ccReg-stubs.o: ccReg-stubs.c ccReg.h
	gcc $(CFLAGS) $(ORB_CFLAGS) -c ccReg-stubs.c

test: test.o epp_xmlcommon.o epp_parser.o epp_gen.o epp-client.o ccReg-common.o ccReg-stubs.o epp_common.o
	gcc -o test -g -Wall $(ORB_LDFLAGS) test.o epp_xmlcommon.o epp_parser.o epp_gen.o epp-client.o ccReg-common.o ccReg-stubs.o epp_common.o $(XML_LIBS)

test.o: test.c epp_common.h epp_parser.h epp_gen.h epp-client.h
	gcc -c -g -O0 -Wall -c test.c

$(IDLOUT): $(IDL)
	$(ORBIT-IDL-2) --noskels $(IDL)

clean:
	-rm -f $(OBJS)
	-rm -f $(IDLOUT)
	-rm -f test test.o epp-client_stub.o
	-rm -f mod_eppd.so

doc: doxy.conf
	doxygen doxy.conf

.PHONY: all build install clean doc

# corba dummy
test_cd: test.o epp_xmlcommon.o epp_gen.o epp_parser.h epp-client_stub.o epp_common.o
	gcc -o test -g -Wall test.o epp_xmlcommon.o epp_parser.o epp_gen.o epp-client_stub.o $(XML_LIBS)

epp-client_stub.o: epp-client_stub.c epp_common.h
	gcc $(CFLAGS) -c epp-client_stub.c
