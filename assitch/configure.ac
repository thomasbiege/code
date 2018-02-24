dnl Process this file with autoconf to create configure.

AC_INIT(assitch,3.0,thomas@suse.de)
AM_INIT_AUTOMAKE(assitch,3.0)
AM_CONFIG_HEADER(include/config.h)

AC_PROG_CC
AC_C_CONST
AC_EXEEXT


CFLAGS="-O2 -Wall"
CPPFLAGS="-I\$(top_srcdir)/include -I/sw/include/"
LDFLAGS="-L/sw/lib"

AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)


dnl check for libnet
AC_CHECK_HEADER(libnet.h, [ lnet_header="yes" ], [ lnet_header="no" ])
if test "$lnet_header" = "yes"; then
	AC_CHECK_LIB(net, libnet_open_raw, AC_DEFINE(HAVE_LIBNET, 1, [libnet support]) LIBNET=$(libnet --libs))
	AC_SUBST(LIBNET)
	CPPFLAGS="$CPPFLAGS $(libnet-config --cflags) $(libnet-config --defines)"
fi

dnl check for libpcap
AC_CHECK_HEADER(pcap.h, [ pcap_header="yes" ], [ pcap_header="no" ])
if test "$pcap_header" = "yes"; then
        AC_CHECK_LIB(pcap, libnet_open_raw, AC_DEFINE(HAVE_LIBPCAP, 1, [libpcap support]) LIBPCAP=-lpcap))
        AC_SUBST(LIBPCAP)
fi

dnl Output the makefile
AC_OUTPUT(Makefile
src/Makefile
include/Makefile
)

