#!/bin/sh -e
# Copyright (c) 2021, Internet Systems Consortium, Inc.
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

TESTPCAP="$srcdir/../../pcap/sample-rfc1035escape.pcap.gz"
../packetq -s "select qname from dns" --json "$TESTPCAP" > test8.out
../packetq -s "select qname from dns" --json --rfc1035 "$TESTPCAP" >> test8.out
../packetq -s "select qname from dns" --csv "$TESTPCAP" >> test8.out
../packetq -s "select qname from dns" --csv --rfc1035 "$TESTPCAP" >> test8.out

diff -uw "$srcdir/test8.gold" test8.out
