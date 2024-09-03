# Copyright (c) 2017-2024 OARC, Inc.
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

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = *.gcda *.gcno *.gcov

SUBDIRS = test

AM_CXXFLAGS = -I$(srcdir) \
  -I$(srcdir)/Murmur \
  -I$(top_srcdir) \
  $(libmaxminddb_CFLAGS)

bin_PROGRAMS = packetq

packetq_SOURCES = dns.cpp dns.h icmp.cpp icmp.h output.h packet_handler.cpp \
  packet_handler.h packetq.cpp packetq.h pcap.cpp pcap.h reader.cpp \
  reader.h refcountstring.h segzip.h server.cpp server.h sql.cpp sql.h \
  tcp.cpp tcp.h variant.h
packetq_LDADD = $(libmaxminddb_LIBS)

dist_packetq_SOURCES = Murmur/MurmurHash3.cpp Murmur/MurmurHash3.h

EXTRA_DIST = regression-test.sh

if ENABLE_GCOV
gcov-local:
	for src in $(packetq_SOURCES) $(dist_packetq_SOURCES); do \
	  gcov -l -r -s "$(srcdir)" "$$src"; \
	done
endif
