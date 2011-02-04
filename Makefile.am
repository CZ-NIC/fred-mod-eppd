ACLOCAL_AMFLAGS = -I m4
include $(top_srcdir)/am_doxygen.am

CLEANFILES = .libs/libmodeppd *~ mod_eppd.la conf/02-fred-mod-eppd-apache.conf \
    Admin.h Admin-common.c Admin-stubs.c \
    Whois.h Whois-common.c Whois-stubs.c \
    Filters.h Filters-common.c Filters-stubs.c \
    EPP.h EPP-common.c EPP-stubs.c \
    Logger.h Logger-common.c Logger-stubs.c \
    _dataTypes.h _dataTypes-common.c _dataTypes-stubs.c \
    Registry.h Registry-common.c Registry-stubs.c


fredschemasdir = ${pkgdatadir}/schemas
fredssldir = ${pkgdatadir}/ssl

noinst_LTLIBRARIES = libcorbadatatypes.la libcorbaregistry.la \
    libcorbaepp.la libcorbalogger.la libcorbawhois.la \
    libcorbafilters.la libcorbaadmin.la libxmleppd.la libmodeppd.la

noinst_DATA        = mod_eppd.la
noinst_PROGRAMS    = epp_test
dist_pkgdata_DATA = conf/02-fred-mod-eppd-apache.conf
dist_fredschemas_DATA = ${srcdir}/schemas/*.xsd ${srcdir}/schemas/README \
			${srcdir}/schemas/ChangeLog
dist_fredssl_DATA = ${srcdir}/ssl/README ${srcdir}/ssl/*.pem
EXTRA_DIST = unconfig.h fred-mod-eppd.spec doxy.conf
BUILT_SOURCES = _dataTypes-common.c Registry-common.c Whois-common.c \
    EPP-common.c Logger-common.c Filters-common.c Admin-common.c

INCL       = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

nodist_libcorbadatatypes_la_SOURCES = _dataTypes.h _dataTypes-common.c _dataTypes-stubs.c 
libcorbadatatypes_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbadatatypes_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbaregistry_la_SOURCES = Registry.h Registry-common.c Registry-stubs.c
libcorbaregistry_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbaregistry_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbaadmin_la_SOURCES = Admin-common.c Admin-stubs.c Admin.h 
libcorbaadmin_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbaadmin_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbawhois_la_SOURCES = Whois-common.c Whois-stubs.c Whois.h 
libcorbawhois_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbawhois_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbafilters_la_SOURCES = Filters-common.c Filters-stubs.c Filters.h
libcorbafilters_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbafilters_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbaepp_la_SOURCES = EPP-common.c EPP-stubs.c EPP.h 
libcorbaepp_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbaepp_la_LDFLAGS = ${ORBIT_LIBS}

nodist_libcorbalogger_la_SOURCES = Logger-common.c Logger-stubs.c Logger.h
libcorbalogger_la_CFLAGS  = ${ORBIT_CFLAGS} 
libcorbalogger_la_LDFLAGS = ${ORBIT_LIBS}

libxmleppd_la_SOURCES = epp_gen.c epp_gen.h epp_parser.c epp_parser.h \
                        epp_xmlcommon.c epp_xmlcommon.h 
libxmleppd_la_CFLAGS  = ${XML_CPPFLAGS}
libxmleppd_la_LDFLAGS = ${XML_LIBS}

libmodeppd_la_SOURCES = epp_common.c epp_common.h epp-client.c epp-client.h \
    logd-client.c logd-client.h mod_eppd.c 
libmodeppd_la_CFLAGS  = ${INCL} -include EPP.h -include Logger.h \
    -include _dataTypes.h -include Registry.h -include Admin.h \
    -include Filters.h -include Whois.h
libmodeppd_la_LIBADD  = libcorbadatatypes.la libcorbaregistry.la \
    libcorbalogger.la libcorbaepp.la libcorbaadmin.la libcorbafilters.la \
    libxmleppd.la libcorbawhois.la

epp_test_SOURCES      = epp_test.c
epp_test_CFLAGS     = ${ORBIT_CFLAGS} 
epp_test_LDADD        = libmodeppd.la ${ORBIT_LIBS}

if DX_COND_html
doc_DATA = @DX_DOCDIR@/html/*
$(doc_DATA): doxygen-doc
MOSTLYCLEANFILES = ${DX_CLEANFILES}
endif

install-exec-local:
	mkdir -p ${DESTDIR}${APACHE_LIBEXECDIR}; \
	${APXS} -S LIBEXECDIR=${DESTDIR}${APACHE_LIBEXECDIR} -i -n 'mod_eppd' mod_eppd.la

uninstall-local:
	rm -rf ${DESTDIR}${APACHE_LIBEXECDIR}/mod_eppd.so

mod_eppd.la: libmodeppd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

_dataTypes-common.c : $(IDLDIR)/_dataTypes.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/_dataTypes.idl

Registry-common.c : $(IDLDIR)/Registry.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Registry.idl

EPP-common.c : $(IDLDIR)/EPP.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/EPP.idl

Logger-common.c : $(IDLDIR)/Logger.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Logger.idl

Admin-common.c : $(IDLDIR)/Admin.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Admin.idl

Filters-common.c : $(IDLDIR)/Filters.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Filters.idl
	
Whois-common.c : $(IDLDIR)/Whois.idl
	$(ORBIT_IDL) --onlytop --noskels $(IDLDIR)/Whois.idl
