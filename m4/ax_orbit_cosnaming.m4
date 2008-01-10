AC_DEFUN([AX_PATH_ORBIT2_COSNAME],
[
    AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
    if test "$PKG_CONFIG" = "no"; then
        no_orbit=yes
    else
        ORBIT_COSNAME_CFLAGS=`${PKG_CONFIG} --cflags ORBit-CosNaming-2.0`
        ORBIT_COSNAME_LIBS=`${PKG_CONFIG} --libs ORBit-CosNaming-2.0`
        AC_SUBST(ORBIT_COSNAME_CFLAGS)
        AC_SUBST(ORBIT_COSNAME_LIBS)
        if test x"$ORBIT_CFLAGS" != x; then
            ORBIT_CFLAGS=`${PKG_CONFIG} --cflags ORBit-2.0 ORBit-CosNaming-2.0`
            ORBIT_LIBS=`${PKG_CONFIG} --libs ORBit-2.0 ORBit-CosNaming-2.0`
            AC_SUBST(ORBIT_CFLAGS)
            AC_SUBST(ORBIT_LIBS)
        fi
    fi

    if test "x$no_orbit" = x; then
        ORBIT_COSNAME_VERSION=`${PKG_CONFIG} --modversion ORBit-CosNaming-2.0`
    fi

])
