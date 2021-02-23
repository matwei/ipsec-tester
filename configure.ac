#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ipsec-tester], [0.0.1], [/dev/null])
#AC_CONFIG_SRCDIR([src/itip.c])
#AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE
AM_PATH_LIBGCRYPT
# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pcap],[pcap_create])

# Checks for header files.
AC_CHECK_HEADERS([pcap/pcap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

PKG_CHECK_MODULES(GMODULE, gmodule-2.0)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
