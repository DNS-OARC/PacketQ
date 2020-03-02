#!/bin/sh -e
# Copyright (c) 2017-2020, OARC, Inc.
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

rm -f test5.out

cat "$srcdir/sql.txt" | grep -v '^#' | while read sql; do
  ../packetq -s "$sql" "$srcdir/../../pcap/sample.pcap.gz" >> test5.out
done

diff -uw "$srcdir/test5.gold" test5.out
