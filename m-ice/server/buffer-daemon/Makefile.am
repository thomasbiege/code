## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= bufferdaemon

bufferdaemon_SOURCES	=	main.c \
				parsecfg.c 

bufferdaemon_LDADD	= -lpthread -lltdl -lmice

noinst_HEADERS	=	bufferdaemon.h \
			intl.h \
			parsecfg.h 
