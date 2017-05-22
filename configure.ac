# Copyright (c) 2017, OARC, Inc.
# Copyright (c) 2011-2017, IIS - The Internet Foundation in Sweden
# All rights reserved.
#
# This file is part of PacketQ.
#
# PacketQ is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PacketQ is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PacketQ.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.61)
AC_INIT([packetq], [1.1.11], [admin@dns-oarc.net], [packetq], [https://github.com/DNS-OARC/packetq/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/packetq.cpp])
AC_CONFIG_HEADER([src/config.h])

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

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/test/Makefile
])
AC_OUTPUT
