ACLOCAL_AMFLAGS = -I m4
CLEANFILES = ${IDL_ALL} .libs/libmodeppd *~ mod_eppd.la

fredschemasdir = ${pkgdatadir}/schemas
fredssldir = ${pkgdatadir}/ssl

noinst_LTLIBRARIES = liborbeppd.la libxmleppd.la libmodeppd.la
noinst_DATA        = mod_eppd.la
noinst_PROGRAMS    = epp_test
dist_pkgdata_DATA = conf/02-fred-mod-eppd-apache.conf
dist_fredschemas_DATA = ${srcdir}/schemas/*.xsd ${srcdir}/schemas/README \
			${srcdir}/schemas/ChangeLog
dist_fredssl_DATA = ${srcdir}/ssl/README ${srcdir}/ssl/*.pem
EXTRA_DIST = unconfig.h fred-mod-eppd.spec 
BUILT_SOURCES = EPP.h EPP-common.c EPP-stubs.c

INCL       = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

IDL_H   = @IDLPREFIX@.h
IDL_S   = @IDLPREFIX@-common.c @IDLPREFIX@-stubs.c
IDL_ALL = ${IDL_S} ${IDL_H}

liborbeppd_la_SOURCES = ${IDL_S} 
liborbeppd_la_CFLAGS  = ${ORBIT_CFLAGS} 
liborbeppd_la_LDFLAGS = ${ORBIT_LIBS}

libxmleppd_la_SOURCES = epp_gen.c epp_gen.h epp_parser.c epp_parser.h \
                        epp_xmlcommon.c epp_xmlcommon.h 
libxmleppd_la_CFLAGS  = ${XML_CPPFLAGS}
libxmleppd_la_LDFLAGS = ${XML_LIBS}

libmodeppd_la_SOURCES = epp_common.c epp_common.h epp-client.c epp-client.h \
                        mod_eppd.c 
libmodeppd_la_CFLAGS  = ${INCL} -include ${IDL_H}
libmodeppd_la_LIBADD  = liborbeppd.la libxmleppd.la

epp_test_SOURCES      = epp_test.c
epp_test_CFLAGS     = ${ORBIT_CFLAGS} 
epp_test_LDADD        = libmodeppd.la ${ORBIT_LIBS}

install-exec-local:
	mkdir -p ${DESTDIR}${APACHE_LIBEXECDIR}; \
	${APXS} -S LIBEXECDIR=${DESTDIR}${APACHE_LIBEXECDIR} -i -n 'mod_eppd' mod_eppd.la

uninstall-local:
	rm -rf ${DESTDIR}${APACHE_LIBEXECDIR}/mod_eppd.so

mod_eppd.la: libmodeppd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

${IDL_ALL}:
	${ORBIT_IDL} --noskels ${IDL}


