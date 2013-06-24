#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([packetq], [1.1.0], [rd@iis.se], [PacketQ],[https://github.com/dotse/packetq/wiki])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE

# Platform-specific tweaks
case $target in
*openbsd*)
    CFLAGS="$CFLAGS -I/usr/local/include"
    CPPFLAGS="$CPPFLAGS -I/usr/local/include"
    LIBS="$LIBS -L/usr/local/lib/";;
esac

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([z], [deflate])
AC_CHECK_LIB([socket], socket)
AC_CHECK_LIB([nsl], inet_ntop)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h limits.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h])
AC_CHECK_HEADER(net/ethernet.h, AC_DEFINE(HAVE_NET_ETHERNET_H,1,[has net/ethernet.h header]))
AC_CHECK_HEADER(net/ethertypes.h, AC_DEFINE(HAVE_NET_ETHERTYPES_H,1,[has net/ethertypes.h header]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero regcomp strtoul])
AC_CHECK_FUNCS([dup2])
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([syslog.h])

# Language used for further checks.
AC_LANG([C])


AC_CONFIG_FILES([Makefile
                 src/Makefile])

AC_OUTPUT

