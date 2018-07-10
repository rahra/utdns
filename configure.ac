AC_PREREQ(2.67)
define([revision], esyscmd([sh -c "echo -n `git log | wc -l`"]))dnl
AC_INIT([utdns], [[1.1.r]revision], [bf@abenteuerland.at])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_SUBST([CFLAGS], [["$CFLAGS -Wall -Wextra"]])
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

