dnl Process this file with autoconf to create configure.

AC_INIT(mice,0.2,thetom@uin4d.de)
AM_INIT_AUTOMAKE(mice,0.2)
AM_CONFIG_HEADER(include/config.h)

AC_PROG_CC
AC_C_CONST
AC_EXEEXT

AM_PROG_LEX
AC_PROG_YACC

CFLAGS="-I\$(top_srcdir)/include $(xml2-config --cflags)"
LDFLAGS="-L\$(top_srcdir)/libs/libmice/ -L\$(top_srcdir)/libs/libmice_parse/ -L\$(top_srcdir)/libs/libmice_pseudo/ $(xml2-config --libs)"

AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl check for LAuS libraries
AC_CHECK_HEADER(laus.h, [ laus_header="yes" ], [ laus_header="no" ])
if test "$laus_header" = "yes"; then
	AC_CHECK_LIB(laus, laus_open, AC_DEFINE(HAVE_LIBLAUS, 1, [liblaus support]) LIBLAUS=-llaus)
	AC_SUBST(LIBLAUS)
fi

AC_CHECK_HEADER(laussrv.h, [ laussrv_header="yes" ], [ laussrv_header="no" ])
if test "$laussrv_header" = "yes"; then
	dnl function call check should be a proc function
	AC_CHECK_LIB(laussrv, laus_api_version, AC_DEFINE(HAVE_LIBLAUSSRV, 1, [liblaussrv support]) LIBLAUSSRV=-llaussrv)
	AC_SUBST(LIBLAUSSRV)
fi



eval conf_dir=\"$sysconfdir\"
AC_DEFINE_UNQUOTED(PATH_CONFIG_DIR, "$conf_dir/M-ICE", [Path of configuration directory])

dnl AC_CHECK_LIBM
dnl AC_SUBST(LIBM)

dnl Output the makefile
AC_OUTPUT(Makefile
client/Makefile
client/dataforwarder/Makefile
etc/Makefile
init-scripts/Makefile
include/Makefile
libs/Makefile
libs/libmice/Makefile
libs/libmice_parse/Makefile
libs/libmice_pseudo/Makefile
server/Makefile
server/buffer-daemon/Makefile
server/reaction-daemon/Makefile
reaction-agents/Makefile
reaction-agents/rid_1_write_to_syslog/Makefile
reaction-agents/rid_2_send_to_alert_db/Makefile
reaction-agents/rid_3_save_to_file/Makefile
reaction-agents/rid_4_countermeasure/Makefile
modules/Makefile
modules/decoding/Makefile
modules/decoding/idmef_twofish/Makefile
modules/decoding/logformat_twofish/Makefile
modules/filter/Makefile
modules/filter/regex/Makefile
modules/format/Makefile
modules/format/simple/Makefile
modules/format/enhanced/Makefile
modules/postprocessing/Makefile
modules/postprocessing/aa_regex/Makefile
modules/postprocessing/act_generic/Makefile
modules/postprocessing/mysql/Makefile
modules/postprocessing/syslog/Makefile
modules/pseudo/Makefile
modules/pseudo/dummy/Makefile
modules/pseudo/symmetric/Makefile
modules/reaction/Makefile
modules/reaction/dummy/Makefile
utils/Makefile
utils/pseudonymizer/Makefile
utils/pseudo_key_gen/Makefile
)

