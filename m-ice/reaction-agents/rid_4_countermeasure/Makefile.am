## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= rid_4_countermeasure

rid_4_countermeasure_SOURCES	=	checksum.c \
					main.c \
					parsecfg.c

rid_4_countermeasure_LDADD	= -lmcrypt -lm -lxml2 -lidmef -lmice

noinst_HEADERS	=	checksum.h \
			idmef-mesg-format.h\
			intl.h\
			parsecfg.h\
			reaction-mesg-format.h\
			rid-mesg-format.h
