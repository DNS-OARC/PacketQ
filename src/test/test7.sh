#!/bin/sh -e
# Copyright (c) 2017-2021, OARC, Inc.
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

../packetq -s "select * from icmp" "$srcdir/../../pcap/icmp.pcap.gz" > test7.out
../packetq -s "select count(*) from icmp" "$srcdir/../../pcap/icmp.pcap.gz" >> test7.out

diff -uw "$srcdir/test7.gold" test7.out
