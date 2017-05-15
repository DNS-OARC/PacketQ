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

set -e

# Simple regression-testing tool that exercises all operators of the
# SQL evaluator and outputs the results.
#
# Usage: regression-test.sh pcap-dump-file
#
# If the script finds a binary called packetq-before, it will execute
# the query on that too and compare the results with diff. So copy the
# packetq binary to packetq-before before you make a change to see the
# effect on the output.

SQL="select s, dst_addr as Dst_addr, qtype as questiontype, lower(src_addr) as lower_src, if(1 and s < 1 or s <= 1 or s > 1 or s >= 1, 't', 'f'), trim(trim('foofoo' || rsplit(src_addr, 1) || 'foofoo', 'foo'), 'bar'), count(*), len(src_addr), sum(msg_size + -1 - 2 % 4 << 3 >> 2 | 3 & ~4) + 1, min(msg_size), max(msg_size), truncate(1.1) as integer, 1.1 as float, sum(src_port + 1.0 - 2.0 / 1.5 * -2.5) + 1.0, max(src_port + 1.0), min(src_port + 1.0), avg(src_port), stdev(src_port), name('rcode', 0) from dns where src_addr like '%' and (qr or not qr) group by src_addr, s having s >= 0 order by s, lower_src, integer, float"

echo "Running packetq, output in regression-test-results"
./packetq -s "$SQL" $1 > regression-test-results

if [ -f ./packetq-before ]
then
    echo "Running packetq-before, output in regression-test-results-before"
    ./packetq-before -s "$SQL" $1 > regression-test-results-before
    diff -u regression-test-results-before regression-test-results
    if [ $? = 0 ]
    then
        echo "No changes in output"
    fi
fi
