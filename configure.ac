AC_PREREQ([2.69])
AC_INIT([libpoc], [1.1.0], [https://github.com/briankwest/libpoc/issues])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_PROG_AR
LT_INIT

AC_PROG_CC
AC_PROG_INSTALL

PKG_CHECK_MODULES([OPENSSL], [openssl], [], [AC_MSG_ERROR([openssl is required])])
PKG_CHECK_MODULES([OPUS], [opus], [], [AC_MSG_ERROR([libopus is required])])

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
