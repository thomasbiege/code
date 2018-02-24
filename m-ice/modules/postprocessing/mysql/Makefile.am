
lib_LTLIBRARIES = mice_mod_pop_mysql.la

mice_mod_pop_mysql_la_SOURCES = mice_mod_pop_mysql.c parsecfg.c
mice_mod_pop_mysql_la_LIBADD = -lmice_parse -lmice_pseudo -lmice -lmysqlclient $(LIBLAUSSRV)  #$(LIBMYSQL)
mice_mod_pop_mysql_la_LDFLAGS = -L/usr/lib/mysql/ -module -version-info 1:0:0

noinst_HEADERS = mice_mod_pop_mysql.h
