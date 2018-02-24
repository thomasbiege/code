## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

sbindir		= /usr/sbin

sbin_PROGRAMS	= reactiondaemon

reactiondaemon_SOURCES	= checksum.c\
			main.c\
			parsecfg.c
reactiondaemon_LDADD	= -lmcrypt -lpthread -lltdl -lmice
