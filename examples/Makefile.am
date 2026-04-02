noinst_PROGRAMS = poc_cli

AM_CFLAGS = \
	-std=c11 -D_GNU_SOURCE \
	-Wall -Wextra \
	-I$(top_srcdir)/include/libpoc \
	-I$(top_srcdir)/src \
	-DLIBPOC_GIT_HASH=\"$(GIT_HASH)\" \
	$(SPEEX_CFLAGS) \
	$(OPENSSL_CFLAGS)

LDADD = \
	$(top_builddir)/src/libpoc.la \
	$(SPEEX_LIBS) \
	$(OPENSSL_LIBS) \
	-lpthread

poc_cli_SOURCES = poc_cli.c
