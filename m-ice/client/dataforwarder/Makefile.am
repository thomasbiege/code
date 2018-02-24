## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= dataforwarder

dataforwarder_SOURCES	=	exchangefd.c \
				main.c \
				parsecfg.c \
				pv.c \
				unixdomainsocket.c
				


dataforwarder_LDADD	= -lmcrypt -lltdl -lmice

noinst_HEADERS	=	dataforwarder.h \
			exchangefd.h \
			intl.h \
			parsecfg.h \
			pv.h \
			unixdomainsocket.h
