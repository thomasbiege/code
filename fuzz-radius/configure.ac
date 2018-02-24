dnl Process this file with autoconf to create configure.

AC_INIT(radius-fuzzer,0.1,thomas@suse.de)
AM_INIT_AUTOMAKE(radius-fuzzer,0.1)
AM_CONFIG_HEADER(include/config.h)

AC_PROG_CC
AC_C_CONST
AC_EXEEXT


CFLAGS="-O2 -Wall"
CPPFLAGS="-I\$(top_srcdir)/include"
LDFLAGS="-L\$(top_srcdir)/lib/"

AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)


dnl Output the makefile
AC_OUTPUT(Makefile
lib/Makefile
src/Makefile
include/Makefile
)

