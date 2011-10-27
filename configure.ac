
AC_INIT([httpcap],[0.1.0],[norihiro@nagater.net])
AC_CONFIG_SRCDIR([config.hin])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_HEADER([config.h:config.hin])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CXX

AC_CHECK_LIB([pcap], [pcap_open_live])

AC_OUTPUT([Makefile])

