# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
## Process this file with automake to produce Makefile.in
## A Makefile.in is supplied, in case you do not have automake.

#AUTOMAKE_OPTIONS=foreign no-dependencies
AUTOMAKE_OPTIONS=foreign
ACLOCAL_AMFLAGS=-I aconf

@SET_MAKE@

bin_PROGRAMS = tac_pwd
sbin_PROGRAMS = tac_plus
tac_pwd_SOURCES = tac_pwd.c
tac_plus_SOURCES = acct.c authen.c author.c choose_authen.c client_count.c \
  config.c default_fn.c default_v0_fn.c do_acct.c do_author.c dump.c enable.c \
	encrypt.c expire.c hash.c maxsessint.c parse.c programs.c pw.c pwlib.c \
	report.c sendauth.c sendpass.c tac_plus.c utils.c
if TACSKEY
tac_plus_SOURCES += skey_fn.c
endif
if TACACECLNT
tac_plus_SOURCES += aceclnt_fn.c
endif
tac_plus_LDFLAGS = -L$(top_srcdir)
tac_plus_LDADD = $(WRAPLIBS) -ltacacs

lib_LTLIBRARIES = libtacacs.la
libtacacs_la_SOURCES = fdes.c maxsess.c md4.c md5.c packet.c
libtacacs_la_CFLAGS = @CFLAGS@ $(WARN) $(DBG) @PROFLAGS@
#libtacacs_la_LIBADD = -lxxx
libtacacs_la_LDFLAGS = -version-info 1:0:0 -version-number 1:0:0
libtacacs_la_LDFLAGS += @LDFLAGS@ @PROFLIBS@

BUILT_SOURCES =

# profiling
CFLAGS += $(WARN) $(DBG) $(PROFLAGS) $(WRAPINCS)
LDADD = $(PROFLIBS)
AM_CPPFLAGS = $(WRAPINCS)
# AM_CPPFLAGS += -I$(top_srcdir)/include @PG_CPPFLAGS@

include_HEADERS = tacacs.h
noinst_HEADERS= fdes.h des_iip.h des_ip.h des_key.h des_s_p.h md4.h mschap.h \
		tac_plus.h expire.h md5.h parse.h pathsl.h

man_gen_MANS = tac_plus.8 tac_plus.conf.5
man_nogen_MANS = tac_pwd.8

man_MANS = $(man_gen_MANS) $(man_nogen_MANS)

# scripts that are built
build_scripts= tac_convert
# scripts that are not-built/static
static_scripts =
pkgdata_SCRIPTS = $(static_scripts) $(build_scripts)
pkgdata_DATA= do_auth.py users_guide

EXTRA_DIST = CHANGES COPYING FAQ INSTALL $(build_scripts:%=%.in) \
		 $(man_nogen_MANS) do_auth.py tacacs+.spec users_guide.in

# '.' is here (and at the front) so that distclean-recursive
# will run make distclean in . after the other dirs
# SUBDIRS = . include lib bin man share

# DIST_COMMON =  Makefile.am Makefile.in TODO aclocal.m4

# no idea why automake screws up cleaning these targets
DISTCLEANFILES= config.status $(build_scripts) users_guide
# CLEANFILES = Makefile $(man_gen_MANS)

# auto_edit does the autoconf variable substitution.  This allows the
# substitution to have the full expansion of the variables, e.g.: $sysconfdir
# will be /prefix/etc instead of ${prefix}/etc.
#
# This is a bit of a PITA, but is the method recommended by the autoconf
# documentation.
auto_edit = sed \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@libexecdir\@,$(libexecdir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@pkglibdir\@,$(pkglibdir),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@PERLV_PATH\@,$(PERLV_PATH),g' \
	-e 's,@TACPLUS_PIDFILE\@,$(TACPLUS_PIDFILE),g' \
	-e 's,@TACPLUS_LOGFILE\@,$(TACPLUS_LOGFILE),g'

tac_convert: Makefile $(srcdir)/tac_convert.in
	rm -f tac_convert tac_convert.tmp; \
	$(auto_edit) $(srcdir)/tac_convert.in >tac_convert.tmp; \
	mv tac_convert.tmp tac_convert; \
	chmod 755 tac_convert

users_guide: Makefile $(srcdir)/users_guide.in
	rm -f users_guide users_guide.tmp; \
	$(auto_edit) $(srcdir)/users_guide.in >users_guide.tmp; \
	mv users_guide.tmp users_guide
