ACLOCAL_AMFLAGS = -I ${top_srcdir}/m4/
CLEANFILES = ${IDL_ALL} .libs/libmodeppd *~

noinst_LTLIBRARIES = liborbeppd.la libxmleppd.la libmodeppd.la
noinst_DATA        = mod_eppd.la
noinst_PROGRAMS    = epp_test

INCLUDES   = ${APACHE_CFLAGS} ${APACHE_CPPFLAGS} ${ORBIT_CFLAGS} ${CPPFLAGS} 
AM_LDFLAGS = ${ORBIT_LIBS} ${LIBS} ${LDFLAGS}

IDL_H   = @IDLPREFIX@.h
IDL_S   = @IDLPREFIX@-common.c @IDLPREFIX@-stubs.c
IDL_ALL = ${IDL_S} ${IDL_H}

liborbeppd_la_SOURCES = ${IDL_S} 
liborbeppd_la_CFLAGS  = ${ORBIT_CFLAGS} 
liborbeppd_la_LDFLAGS = ${ORBIT_LIBS}

libxmleppd_la_SOURCES = epp_gen.c epp_parser.c epp_xmlcommon.c
libxmleppd_la_CFLAGS  = ${XML_CPPFLAGS}
libxmleppd_la_LDFLAGS = ${XML_LIBS}

libmodeppd_la_SOURCES = epp_common.c epp-client.c mod_eppd.c 
libmodeppd_la_CFLAGS  = ${INCLUDES} -include ${IDL_H}
libmodeppd_la_LIBADD  = liborbeppd.la libxmleppd.la

epp_test_SOURCES      = epp_test.c
epp_test_LDADD        = libmodeppd.la 

install-exec-local:
	${APXS} -i -n 'mod_eppd' mod_eppd.la

mod_eppd.la: libmodeppd.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${ORBIT_CFLAGS} ${AM_LDFLAGS}

${IDL_ALL}:
	${ORBIT_IDL} --noskels ${IDL}


