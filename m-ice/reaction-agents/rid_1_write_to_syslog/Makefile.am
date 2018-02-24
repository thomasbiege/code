## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= rid_1_write_to_syslog

rid_1_write_to_syslog_SOURCES	=	main.c \
					parsecfg.c

rid_1_write_to_syslog_LDADD	= -lmice

noinst_HEADERS	= 	idmef-mesg-format.h \
			intl.h \
			parsecfg.h \
			rid-mesg-format.h
