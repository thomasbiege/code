# Makefile.in generated by automake 1.7.6 from Makefile.am.
# init-scripts/Makefile.  Generated from Makefile.in by configure.

# Copyright 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003
# Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.



srcdir = .
top_srcdir = ..

pkgdatadir = $(datadir)/mice
pkglibdir = $(libdir)/mice
pkgincludedir = $(includedir)/mice
top_builddir = ..

am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
INSTALL = /usr/bin/ginstall -c
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
host_triplet = i686-suse-linux
ACLOCAL = ${SHELL} /home/thomas/CVS-Projects/m-ice/missing --run aclocal-1.7
AMDEP_FALSE = #
AMDEP_TRUE = 
AMTAR = ${SHELL} /home/thomas/CVS-Projects/m-ice/missing --run tar
AR = ar
AUTOCONF = ${SHELL} /home/thomas/CVS-Projects/m-ice/missing --run autoconf
AUTOHEADER = ${SHELL} /home/thomas/CVS-Projects/m-ice/missing --run autoheader
AUTOMAKE = ${SHELL} /home/thomas/CVS-Projects/m-ice/missing --run automake-1.7
AWK = gawk
CC = gcc
CCDEPMODE = depmode=gcc3
CFLAGS = -I$(top_srcdir)/include -I/usr/include/libxml2
CPP = gcc -E
CPPFLAGS = 
CXX = g++
CXXCPP = g++ -E
CXXDEPMODE = depmode=gcc3
CXXFLAGS = -g -O2
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
ECHO = echo
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = grep -E
EXEEXT = 
F77 = g77
FFLAGS = -g -O2
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = ${SHELL} $(install_sh) -c -s
LDFLAGS = -L$(top_srcdir)/libs/libmice/ -L$(top_srcdir)/libs/libmice_parse/ -L$(top_srcdir)/libs/libmice_pseudo/ -L/usr/lib -lxml2 -lz -lpthread -lm
LEX = flex
LEXLIB = -lfl
LEX_OUTPUT_ROOT = lex.yy
LIBLAUS = 
LIBLAUSSRV = 
LIBOBJS = 
LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBTOOL_DEPS = ./ltmain.sh
LN_S = ln -s
LTLIBOBJS = 
MAKEINFO = ${SHELL} /home/thomas/CVS-Projects/m-ice/missing --run makeinfo
OBJEXT = o
PACKAGE = mice
PACKAGE_BUGREPORT = thetom@uin4d.de
PACKAGE_NAME = mice
PACKAGE_STRING = mice 0.2
PACKAGE_TARNAME = mice
PACKAGE_VERSION = 0.2
PATH_SEPARATOR = :
RANLIB = ranlib
SET_MAKE = 
SHELL = /bin/sh
STRIP = strip
VERSION = 0.2
YACC = bison -y
ac_ct_AR = ar
ac_ct_CC = gcc
ac_ct_CXX = g++
ac_ct_F77 = g77
ac_ct_RANLIB = ranlib
ac_ct_STRIP = strip
am__fastdepCC_FALSE = #
am__fastdepCC_TRUE = 
am__fastdepCXX_FALSE = #
am__fastdepCXX_TRUE = 
am__include = include
am__leading_dot = .
am__quote = 
bindir = ${exec_prefix}/bin
build = i686-suse-linux
build_alias = 
build_cpu = i686
build_os = linux
build_vendor = suse
datadir = ${prefix}/share
exec_prefix = ${prefix}
host = i686-suse-linux
host_alias = 
host_cpu = i686
host_os = linux
host_vendor = suse
includedir = ${prefix}/include
infodir = ${prefix}/info
install_sh = /home/thomas/CVS-Projects/m-ice/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localstatedir = ${prefix}/var
mandir = ${prefix}/man
oldincludedir = /usr/include
prefix = /usr/local
program_transform_name = s,x,x,
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com

sysconfdir := ${prefix}/etc/init.d/
target_alias = 

MAINTAINERCLEANFILES = Makefile.in

dist_sysconf_DATA = MICE-bufferdaemon \
			MICE-bufferdaemon-aa \
			MICE-bufferdaemon-mngmthost \
			MICE-bufferdaemon-rawlogdb \
			MICE-dataforwarder \
			MICE-reactiondaemon \
			MICE-rid_1_write_to_syslog \
			MICE-rid_2_send_to_alert_db \
			MICE-rid_3_save_to_file \
			MICE-rid_4_countermeasure

subdir = init-scripts
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/include/config.h
CONFIG_CLEAN_FILES =
DIST_SOURCES =
DATA = $(dist_sysconf_DATA)

DIST_COMMON = $(dist_sysconf_DATA) Makefile.am Makefile.in
all: all-am

.SUFFIXES:
$(srcdir)/Makefile.in:  Makefile.am  $(top_srcdir)/configure.ac $(ACLOCAL_M4)
	cd $(top_srcdir) && \
	  $(AUTOMAKE) --gnu  init-scripts/Makefile
Makefile:  $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

distclean-libtool:
	-rm -f libtool
uninstall-info-am:
dist_sysconfDATA_INSTALL = $(INSTALL_DATA)
install-dist_sysconfDATA: $(dist_sysconf_DATA)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	@list='$(dist_sysconf_DATA)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f="`echo $$p | sed -e 's|^.*/||'`"; \
	  echo " $(dist_sysconfDATA_INSTALL) $$d$$p $(DESTDIR)$(sysconfdir)/$$f"; \
	  $(dist_sysconfDATA_INSTALL) $$d$$p $(DESTDIR)$(sysconfdir)/$$f; \
	done

uninstall-dist_sysconfDATA:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_sysconf_DATA)'; for p in $$list; do \
	  f="`echo $$p | sed -e 's|^.*/||'`"; \
	  echo " rm -f $(DESTDIR)$(sysconfdir)/$$f"; \
	  rm -f $(DESTDIR)$(sysconfdir)/$$f; \
	done
tags: TAGS
TAGS:

ctags: CTAGS
CTAGS:

DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)

top_distdir = ..
distdir = $(top_distdir)/$(PACKAGE)-$(VERSION)

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's|.|.|g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's|.|.|g'`; \
	list='$(DISTFILES)'; for file in $$list; do \
	  case $$file in \
	    $(srcdir)/*) file=`echo "$$file" | sed "s|^$$srcdirstrip/||"`;; \
	    $(top_srcdir)/*) file=`echo "$$file" | sed "s|^$$topsrcdirstrip/|$(top_builddir)/|"`;; \
	  esac; \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  dir=`echo "$$file" | sed -e 's,/[^/]*$$,,'`; \
	  if test "$$dir" != "$$file" && test "$$dir" != "."; then \
	    dir="/$$dir"; \
	    $(mkinstalldirs) "$(distdir)$$dir"; \
	  else \
	    dir=''; \
	  fi; \
	  if test -d $$d/$$file; then \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -pR $(srcdir)/$$file $(distdir)$$dir || exit 1; \
	    fi; \
	    cp -pR $$d/$$file $(distdir)$$dir || exit 1; \
	  else \
	    test -f $(distdir)/$$file \
	    || cp -p $$d/$$file $(distdir)/$$file \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(DATA)

installdirs:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  INSTALL_STRIP_FLAG=-s \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install
mostlyclean-generic:

clean-generic:

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
	-test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
clean: clean-am

clean-am: clean-generic clean-libtool mostlyclean-am

distclean: distclean-am

distclean-am: clean-am distclean-generic distclean-libtool

dvi: dvi-am

dvi-am:

info: info-am

info-am:

install-data-am:

install-exec-am: install-dist_sysconfDATA

install-info: install-info-am

install-man:

installcheck-am:

maintainer-clean: maintainer-clean-am

maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-generic mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-dist_sysconfDATA uninstall-info-am

.PHONY: all all-am check check-am clean clean-generic clean-libtool \
	distclean distclean-generic distclean-libtool distdir dvi \
	dvi-am info info-am install install-am install-data \
	install-data-am install-dist_sysconfDATA install-exec \
	install-exec-am install-info install-info-am install-man \
	install-strip installcheck installcheck-am installdirs \
	maintainer-clean maintainer-clean-generic mostlyclean \
	mostlyclean-generic mostlyclean-libtool pdf pdf-am ps ps-am \
	uninstall uninstall-am uninstall-dist_sysconfDATA \
	uninstall-info-am

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
