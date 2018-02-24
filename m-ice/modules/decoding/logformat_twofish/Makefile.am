## Makefile.am -- Process this file with automake to produce Makefile.in

MAINTAINERCLEANFILES = Makefile.in

lib_LTLIBRARIES					= mice_mod_dec_logformat_twofish.la
mice_mod_dec_logformat_twofish_la_SOURCES	= mice_mod_dec_logformat_twofish.c \
						checksum.c\
						parsecfg.c
mice_mod_dec_logformat_twofish_la_LIBADD	= -lmcrypt -lmice
mice_mod_dec_logformat_twofish_la_LDFLAGS	= -module -version-info 1:0:0

