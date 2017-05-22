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

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = test

AM_CXXFLAGS = -I$(srcdir) \
    -I$(top_srcdir) \
    -std=c++0x \
    -Wall -Wno-parentheses -Wno-switch -Wno-sign-compare -Wno-char-subscripts

bin_PROGRAMS = packetq

packetq_SOURCES = dns.cpp icmp.cpp MurmurHash3.cpp packet_handler.cpp \
    packetq.cpp pcap.cpp reader.cpp server.cpp sql.cpp tcp.cpp

dist_packetq_SOURCES = dns.h icmp.h MurmurHash3.h output.h packet_handler.h \
    packetq.h pcap.h reader.h refcountstring.h segzip.h server.h sql.h tcp.h \
    variant.h
