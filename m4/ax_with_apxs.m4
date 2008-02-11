# some code taken from mod_python's (http://www.modpython.org/) configure.in

AC_DEFUN([AX_WITH_APXS],
[

# check for --with-apxs
AC_MSG_CHECKING(for --with-apxs)
AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=PATH], [Path to apxs]),
[
  if test -x "$withval"
  then
    AC_MSG_RESULT([$withval executable, good])
    APXS=$withval
  else
    echo
    AC_MSG_ERROR([$withval not found or not executable])
  fi
],
AC_MSG_RESULT(no))

# find apxs
if test -z "$APXS"; then
  AC_PATH_PROGS([APXS],[apxs2 apxs],[false],[${PATH}:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin])
  test "${APXS}" = "false" && AC_MSG_ERROR([failed to find apxs. Try using --with-apxs])
fi

AC_SUBST(APXS)
])
