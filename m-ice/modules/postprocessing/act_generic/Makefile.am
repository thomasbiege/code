## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = mice_mod_pop_act_generic.la

mice_mod_pop_act_generic_la_SOURCES = mice_mod_pop_act_generic.c checksum.c parsecfg.c
mice_mod_pop_act_generic_la_LIBADD = -lxml2 -lntp -lidmef -lmice
mice_mod_pop_act_generic_la_LDFLAGS = -module -version-info 1:0:0

noinst_HEADERS = mice_mod_pop_act_generic.h
