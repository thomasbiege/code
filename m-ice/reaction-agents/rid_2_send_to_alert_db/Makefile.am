## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= rid_2_send_to_alert_db

rid_2_send_to_alert_db_SOURCES	=	main.c \
					parsecfg.c

rid_2_send_to_alert_db_LDADD	=	-L/usr/lib/mysql/ -lmysqlclient -lidmef -lm -lxml2 -lmcrypt -lmice

noinst_HEADERS	= 	idmef-mesg-format.h \
			intl.h \
			parsecfg.h \
			rid-mesg-format.h
