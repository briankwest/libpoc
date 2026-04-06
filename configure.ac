AC_PREREQ([2.69])
AC_INIT([libpoc], [1.0.2], [https://github.com/briankwest/libpoc/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_PROG_AR
LT_INIT

AC_PROG_CC
AC_PROG_INSTALL

PKG_CHECK_MODULES([SPEEX], [speex], [], [AC_MSG_ERROR([libspeex is required])])
PKG_CHECK_MODULES([OPENSSL], [openssl], [], [AC_MSG_ERROR([openssl is required])])

dnl Opus is optional — auto-detected, graceful fallback if absent
PKG_CHECK_MODULES([OPUS], [opus], [have_opus=yes], [have_opus=no])
AM_CONDITIONAL([HAVE_OPUS], [test "x$have_opus" = "xyes"])
if test "x$have_opus" = "xyes"; then
  AC_DEFINE([HAVE_OPUS], [1], [Have libopus])
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    include/Makefile
    tests/Makefile
    examples/Makefile
    libpoc.pc
])
AC_OUTPUT
