noinst_PROGRAMS = poc_cli poc_server

AM_CFLAGS = \
	-std=c11 -D_GNU_SOURCE \
	-Wall -Wextra \
	-I$(top_srcdir)/include/libpoc \
	-I$(top_srcdir)/src \
	-DLIBPOC_GIT_HASH=\"$(GIT_HASH)\" \
	$(SPEEX_CFLAGS) \
	$(OPENSSL_CFLAGS) \
	$(OPUS_CFLAGS)

LDADD = \
	$(top_builddir)/src/libpoc.la \
	$(SPEEX_LIBS) \
	$(OPENSSL_LIBS) \
	$(OPUS_LIBS) \
	-lpthread \
	-lm

poc_cli_SOURCES = poc_cli.c linenoise.c

poc_server_SOURCES = poc_server.c linenoise.c

noinst_HEADERS = linenoise.h

EXTRA_DIST = poc_server.conf.ini
