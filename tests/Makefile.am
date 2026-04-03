check_PROGRAMS = test_libpoc

test_libpoc_SOURCES = \
	test_main.c \
	test_util.c \
	test_crypto.c \
	test_tcp_frame.c \
	test_msg_build.c \
	test_msg_parse.c \
	test_codec.c \
	test_encrypt.c \
	test_gps.c \
	test_fec.c

test_libpoc_CFLAGS = \
	-std=c11 -D_GNU_SOURCE \
	-Wall -Wextra \
	-I$(top_srcdir)/include/libpoc \
	-I$(top_srcdir)/src \
	$(SPEEX_CFLAGS) \
	$(OPENSSL_CFLAGS)

test_libpoc_LDADD = \
	$(top_builddir)/src/libpoc.la \
	$(SPEEX_LIBS) \
	$(OPENSSL_LIBS) \
	-lpthread \
	-lm

noinst_PROGRAMS = test_codec_wav

test_codec_wav_SOURCES = test_codec_wav.c
test_codec_wav_CFLAGS = $(test_libpoc_CFLAGS) -Wno-format-truncation
test_codec_wav_LDADD = $(test_libpoc_LDADD)

TESTS = test_libpoc
