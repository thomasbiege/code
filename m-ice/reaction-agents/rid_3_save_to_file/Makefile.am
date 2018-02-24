## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= rid_3_save_to_file

rid_3_save_to_file_SOURCES	=	main.c \
					parsecfg.c

rid_3_save_to_file_LDADD	= -lmice

noinst_HEADERS	=	idmef-mesg-format.h \
			intl.h \
			parsecfg.h \
			rid-mesg-format.h
