AC_PREREQ(2.67)
define([svnversion], esyscmd([sh -c "echo -n `svnversion | tr -d 'M'`"]))dnl
AC_INIT([utdns], [[1.0.r]svnversion], [bf@abenteuerland.at])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_SUBST([CFLAGS], [["$CFLAGS -Wall -Wextra"]])
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

