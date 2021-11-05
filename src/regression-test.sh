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

#set -e
DIR=/tmp/test/packetq
mkdir -p $DIR
typeset -i test
test=0
cd $(dirname $0)
for SQL in \
	"select qname as CertainQnames, qtype as Qtype, count(1) as count from dns where (qname='localhost' or qname like '%.root-servers.net') and qr==0 group by CertainQnames,Qtype order by count desc ;" \
	'select qtype as Qtype, qname as Qname, count(1) as count from dns where qclass==3 and qr==0 group by Qtype,Qname order by count desc ;' \
	'select rcode as Rcode, if(qr==1,dst_addr,src_addr) as ClientAddr, count(1) as count from dns where qr==1 group by Rcode,ClientAddr order by count desc limit 50;' \
	"select 'ALL' as All, if(ether_type==34525,rsplit(src_addr,7,':')||':'||rsplit(src_addr,6,':')||':'||rsplit(src_addr,5,':')||':'||rsplit(src_addr,4,':')||':'||rsplit(src_addr,3,':')||'::',rsplit(src_addr,3)||'.'||rsplit(src_addr,2)||'.'||rsplit(src_addr,1)||'.0') as ClientSubnet, count(1) as count from dns where qr==0 group by All,ClientSubnet order by count,ClientSubnet desc limit 200;;" \
	"select 'ALL' as All, subnet(src_addr,24,96) as ClientSubnet, count(1) as count from dns where qr==0 group by All,ClientSubnet order by count desc,ClientSubnet limit 200;;" \
	"select if(rsplit(qname,1)='de','ok','non-auth-tld') as Class, if(ether_type==34525,rsplit(src_addr,7,':')||':'||rsplit(src_addr,6,':')||':'||rsplit(src_addr,5,':')||':'||rsplit(src_addr,4,':')||':'||rsplit(src_addr,3,':')||'::',rsplit(src_addr,3)||'.'||rsplit(src_addr,2)||'.'||rsplit(src_addr,1)||'.0') as ClientSubnet, count(1) as count from dns where qr==0 group by Class,ClientSubnet order by count,ClientSubnet,Class desc limit 200;;" \
	"select if(qr==1,'sent','recv') as Direction, if(protocol==6,'tcp',if(protocol==17,'udp',if(protocol==1,'icmp',if(protocol==58,'ipv6-icmp',protocol)))) as IPProto, count(1) as count from dns  group by Direction,IPProto order by count,Direction desc ;" \
	"select if(ether_type==34525,'IPv6','IPv4') as IPVersion, qtype as Qtype, count(1) as count from dns where qr==0 group by IPVersion,Qtype order by count desc ;" \
	"select 'ALL' as All, do, edns0, edns_version, extended_rcode, z, if(do==1,'set','clr') as D0, count(1) as count from dns where qr==0 group by All,do,D0,edns0,edns_version,extended_rcode,z order by count desc ;" \
	"select 'ALL' as All, if(edns0,edns_version,'none') as EDNSVersion, count(1) as count from dns where qr==0 group by All,EDNSVersion order by count desc ;" \
	"select 'ALL' as All, if(qname like 'xn--%','idn','normal') as IDNQname, count(1) as count from dns where qr==0 group by All,IDNQname order by count desc ;" \
	"select 'ALL' as All, lower(rsplit(qname,1)) as TLD, count(1) as count from dns where qr==0 and (qname like 'xn--%') group by All,TLD order by count,TLD desc ;" \
	"select 'ALL' as All, if(qr==1,dst_addr,src_addr) as ClientAddr, count(1) as count from dns where qr==0 and (qtype=28 or qtype=38) and (qname like '%.root-servers.net') group by All,ClientAddr order by count desc limit 50;;" \
	"select 'ALL' as All, opcode as Opcode, count(1) as count from dns where qr==0 group by All,Opcode order by count desc ;" \
	"select 'ALL' as All, qtype as Qtype, count(1) as count from dns where qr==0 group by All,Qtype order by count desc ;" \
	'select qtype as Qtype, len(qname) as QnameLen, count(1) as count from dns where qr==0 group by Qtype,QnameLen order by count,QnameLen,Qtype desc ;' \
	'select qtype as Qtype, lower(rsplit(qname,1)) as TLD, count(1) as count from dns where qr==0 and (qtype=1 or qtype=2 or qtype=5 or qtype=6 or qtype=12 or qtype=15 or qtype=28 or qtype=38 or qtype=255) group by Qtype,TLD order by count,TLD,Qtype desc limit 200;;' \
	"select 'ALL' as All, rcode as Rcode, count(1) as count from dns where qr==1 group by All,Rcode order by count desc ;" \
	'select rcode as Rcode, msg_size as ReplyLen, count(1) as count from dns where qr==1 group by Rcode,ReplyLen order by count desc ;' \
	"select 'ALL' as All, rd as RD, count(1) as count from dns where qr==0 group by All,RD order by count desc ;" \
	"select if(protocol==6,'tcp',if(protocol==17,'udp',protocol)) as Transport, qtype as Qtype, count(1) as count from dns where qr==0 group by Transport,Qtype order by Transport,Qtype,count desc ;" \
	"select s, dst_addr as Dst_addr, qtype as questiontype, lower(src_addr) as lower_src, if(1 and s < 1 or s <= 1 or s > 1 or s >= 1, 't', 'f'), trim(trim('foofoo' || rsplit(src_addr, 1) || 'foofoo', 'foo'), 'bar'), count(*), len(src_addr), sum(msg_size + -1 - 2 % 4 << 3 >> 2 | 3 & ~4) + 1, min(msg_size), max(msg_size), truncate(1.1) as integer, 1.1 as float, sum(src_port + 1.0 - 2.0 / 1.5 * -2.5) + 1.0, max(src_port + 1.0), min(src_port + 1.0), avg(src_port), stdev(src_port), name('rcode', 0) from dns where src_addr like '%' and (qr or not qr) group by src_addr, s having s >= 0 order by s, dst_addr, lower_src, integer, float" \
	"select name( 'qtype' , qtype ) as qt, count(*) as count from dns group by qtype order by count desc;"\
	"select count(*) as count, lower(rsplit(qname,1)) as tld, istld(tld) as flag from dns group by tld order by count desc limit 50;" \
        ;
do
    test=$test+1
    new=$(./packetq --version | tr " " "_")
    echo ""
    if [ ${#SQL} -gt 200 ]; then ellipsis="..."; else ellipsis=""; fi
    echo "Test $test: '${SQL:0:200}$ellipsis'"
    t_new=$(/usr/bin/time -f "%e" ./packetq --tlds /usr/share/packetq/tlds -s "$SQL" $1 2>&1 > $DIR/$new.test$test.result)
    e_new=$?
    echo "  Comparing $new against available binaries:"
    for prev in $(ls ../../packetq*/src/packetq); do
	old=$($prev --version | cut -d " " -f 2)
	ver=$(printf "%-20s" $old)
	bin=$(printf "%-48s" $prev)
	t_old=$(/usr/bin/time -f "%e" $prev -s "$SQL" $1 2>&1 > $DIR/$old.test$test.result)
	e_old=$?
	if [ $e_new = 0 -a $e_old = 0 -a "$t_old" != "0.00" ]; then
	    echo -e "  $bin $ver: $t_old --> $t_new ($(python -c "print '%5.2f  %d%%' % ($t_new - $t_old, ($t_new-$t_old)*100/$t_old)"))"
	else
	    echo -e "  $bin $ver: $t_old --> $t_new ($ver Failed)"
	fi
	diff -u $DIR/$old.test$test.result $DIR/$new.test$test.result > $DIR/$new.test$test.diff
	if [ $? = 0 ]; then
	    #echo "Test $test: No changes in output"
	    true
	else
	    head -n 20 $DIR/$new.test$test.diff
	fi
    done
done
