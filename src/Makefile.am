lib_LTLIBRARIES = libpoc.la

libpoc_la_SOURCES = \
	poc_ctx.c \
	poc_tcp.c \
	poc_udp.c \
	poc_msg_build.c \
	poc_msg_parse.c \
	poc_codec.c \
	poc_crypto.c \
	poc_encrypt.c \
	poc_gps.c \
	poc_fec.c \
	poc_util.c

libpoc_la_CFLAGS = \
	-std=c11 -D_GNU_SOURCE \
	-Wall -Wextra \
	-I$(top_srcdir)/include/libpoc \
	-I$(top_srcdir)/src \
	-DLIBPOC_GIT_HASH=\"$(GIT_HASH)\" \
	$(SPEEX_CFLAGS) \
	$(OPENSSL_CFLAGS)

libpoc_la_LDFLAGS = -version-info 0:0:0

libpoc_la_LIBADD = \
	$(SPEEX_LIBS) \
	$(OPENSSL_LIBS) \
	-lpthread \
	-lm
