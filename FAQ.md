# FAQ and Examples

## What output-options are there?

You can get XML, CSV, JSON or TABLE (CSV with spaces).

## Does PacketQ conform to the SQL standard ?

The short answer is no.

Packet implements an SQL like select function with some notable omissions like:

* No 3 value logic i.e. theres no special NULL value
* No supports for joins or subqueries
* No support for the distinct keyword
* No support for like in where statements

Refer to the file [grammar](src/grammar) for supported statements.

## How do I return full packetdata for the first 3 dns packets?

Use this SQL-statement.

```shell
$ packetq -s "select * from dns limit 3" packets.pcap
```

## How do I check which qname is queried the most?

```shell
$ packetq -s "select qname,count(*) as count from dns group by qname order by count desc limit 1 " packets.pcap
```

```javascript
[
{ "table_name": "result",
    "head": [
      { "name": "qname","type": "text" },
      { "name": "count","type": "int" }
    ],
    "data": [ ["se.",2747]  ]
  }
]
```

## How do I check which server that makes the most queries?

```shell
$ packetq -s "select src_addr,count(*) as count from dns group by src_addr order by count desc limit 1" packets.pcap
```

```javascript
[
  {
    "table_name": "result",
    "head": [
      { "name": "src_addr","type": "text" },
      { "name": "count","type": "int" }
    ],
    "data": [
["::127.0.0.1",1849]
    ]
  }
]
```

## I have 90000000 packets in a file, how can I speed up the query?

By using the sample-keyword before the actual query, it selects only every Xth
packet and speeds up the query substantially. The amount of time saved by this
command will be different on different systems, at some point the time it takes
to read the file from disk will be longer than the time spent on processing.
In other words, the full file will have to be read from disk regardless.
This command also saved RAM.

```shell
$ ./packetq -s "sample 1000; select count(*) from dns" ~/pcap/*
```

```javascript
[  {
    "table_name": "result",
    "head": [ { "name": "count(1)","type": "int" }],
    "data": [ [90000]] }]
```

## How do I extract parts of the qname and group using this, like the domain-name?

Using the rsplit-function you can split values based on chars (like the dot).
This query extract the two lowest levels (the domain for the .se-zone) and
makes a top-10 list.

```shell
$ packetq -s "select count(*) as Count, lower(rsplit(qname,2)||'.'||rsplit(qname,1)) as Domain from dns group by domain order by count desc limit 10" peak/07/G.ns.se-20110408-074500-em0.gz
```

```javascript
[
  {
    "table_name": "result",
    "head": [
      { "name": "Count","type": "int" },
      { "name": "Domain","type": "text" }
    ],
    "data": [
[5130,"pp.se"],
[1686,"netnod.se"],
[1448,".se"],
[1318,"domainnetwork.se"],
[936,"ballou.se"],
[867,"loopia.se"],
[784,"ns.se"],
[736,"sonera.se"],
[694,"digidns.se"],
[639,"prq.se"]
    ]
  }
]
```

## How do I make a top-list of client-IPs?

PacketQ supports looking at packets to and from the nameserver/resolver.
But since the client-IP changes from src_addr to dst_addr if the packet is
an reply, we have to use the if-function to extract the client-IP.

```shell
$ packetq -s "select count(*) as Count, if(qr=1,dst_addr,src_addr) as Source from dns group by source order by count desc limit 15" peak/07/G.ns.se-20110408-070000-em0.gz
```

```javascript
[
  {
    "table_name": "result",
    "head": [
      { "name": "Count","type": "int" },
      { "name": "Source","type": "text" }
    ],
    "data": [
[1021,"202.67.195.41"],
[929,"91.191.143.34"],
[638,"195.84.206.2"],
[582,"202.101.173.146"],
[490,"2a02:aa0:0:10:214:4fff:fef2:61a0"],
[438,"80.251.201.177"],
[436,"192.89.123.231"],
[426,"81.228.8.143"],
[409,"81.228.8.69"],
[402,"65.54.237.136"],
[368,"81.228.8.144"],
[352,"213.50.29.170"],
[342,"217.28.204.2"],
[318,"2001:6f0:0:1::2:3"],
[297,"81.228.9.132"]
    ]
  }
]
```

## Does PacketQ support IPv6?

Yes, it does. See the above result.

## Can I make a query that lists all resolvers that are broken?

If by broken you mean resolvers that are repeating the same query over and
over again, then yes.

```shell
$ packetq -s "select count(*) as Count,qname,if(qr=1,dst_addr,src_addr) as Source,qtype from dns group by qname,source,qtype order by count desc limit 10" peak/07/G.ns.se-20110408-070000-em0.gz
```

```javascript
[
  {
    "table_name": "result",
    "head": [
      { "name": "Count","type": "int" },
      { "name": "qname","type": "text" },
      { "name": "Source","type": "text" },
      { "name": "qtype","type": "int" }
    ],
    "data": [
[607,"se.","195.84.206.2",48],
[375,"ns.digidns.se.","202.67.195.41",1],
[330,"sas.sas.se.","202.67.195.41",1],
[316,"NS.DIGIDNS.SE.","202.67.195.41",1],
[147,"se.","62.80.200.144",48],
[42,"se.","94.232.104.58",48],
[40,"_ldap._tcp.pdc._msdcs.telemgmt.se.","213.115.146.180",33],
[40,"se.","83.12.96.122",48],
[34,"www.membran.se.","217.73.15.38",1],
[28,"fc.edu.upplandsvasby.se.","193.12.6.247",1]
    ]
  }
]
```

## Can I get a list of what qtypes are used the most?

Yes, and PacketQ can even translate the headers into text for you by using
the NAME-function.

```shell
$ packetq -s "SELECT NAME( 'qtype' , qtype ) AS qt, COUNT(*) AS antal FROM dns GROUP BY qtype ORDER BY Antal DESC" peak/07/G.ns.se-20110408-070000-em0.gz
```

```javascript
[
  {
    "table_name": "result",
    "head": [
      { "name": "qt","type": "text" },
      { "name": "antal","type": "int" }
    ],
    "data": [
["A",59908],
["AAAA",13076],
["MX",10527],
["DS",7545],
["NS",1666],
["DNSKEY",1077],
["TXT",969],
["A6",563],
["*",556],
["SRV",197],
["SPF",145],
["SOA",126],
["PTR",60],
["CNAME",47],
["NAPTR",3]
    ]
  }
]
```

## OK, give me a more advanced query to chew on?

Absolutely! This query uses the TRUNCATE-keyword to split the stats into
different timeperiods. In this case 10-second periods. This is great for
line-graphs that you can make using Excel or similar tools.

We then get the stats by using conditions like ((rcode=0) and (an_count=0))
to identify packets that resulted in referrals and (rcode=3) to see which
packets got an nxdomain back and so on. By using the SUM-function they are
all counted and since we want q/sec as our output, divided by 10.

Try to import the result below into Excel!

```shell
$ packetq --table -s "select s as timestamp, count(*)/10 as total, sum((rcode=0) and (an_count=0))/10 as referral, sum(rcode=3)/10 as nxdomain, sum((rcode=0) and (an_count>0))/10 as success, sum(rd)/10 as recursion, sum(ether_type=34525)/10 as IPV6, sum(protocol=6)/10 as TCP from dns group by truncate(s/10) " peak/07/G.ns.se-20110408-071000-em0.gz
"timestamp","total","referral","nxdomain","success","recursion","IPV6","TCP"
1302246609 ,822.5  ,304.3     ,515.5     ,2        ,527        ,15.3  ,0
1302246619 ,1135.9 ,330.8     ,797.8     ,6        ,817.2      ,16.7  ,0
1302246629 ,1475.2 ,317.8     ,1152.1    ,4.4      ,1170       ,17.9  ,0
1302246639 ,1774.7 ,344.9     ,1424.8    ,3.8      ,1461.4     ,14.2  ,0
1302246649 ,2014.4 ,350.6     ,1658.5    ,4.4      ,1712.4     ,15.9  ,0
1302246659 ,2136.4 ,346.7     ,1786.2    ,2.5      ,1834.9     ,15.4  ,0
1302246669 ,2212.1 ,336       ,1872      ,3        ,1918.3     ,16.1  ,0.1
1302246679 ,2292.4 ,336.7     ,1952.6    ,2.1      ,1999.7     ,16.4  ,0
1302246689 ,2337   ,324.2     ,2004.6    ,6.8      ,2052.6     ,13.8  ,0
1302246699 ,2410.8 ,315.9     ,2084.7    ,9.1      ,2121.7     ,12.3  ,0
1302246709 ,2437.5 ,311.9     ,2113      ,12       ,2151.3     ,14.2  ,0
1302246719 ,2488.1 ,302.8     ,2178.5    ,5.7      ,2214.8     ,13.8  ,0
1302246729 ,2496   ,327.4     ,2163.6    ,3.8      ,2202.5     ,15    ,0
1302246739 ,2546.7 ,333.3     ,2200.2    ,11.6     ,2234.9     ,16.7  ,0
1302246749 ,2473.3 ,314.1     ,2150.4    ,7.9      ,2180.8     ,15.6  ,0
1302246759 ,2476.2 ,313.4     ,2146.8    ,14.5     ,2175.3     ,12    ,0
1302246769 ,2472   ,324.9     ,2133.2    ,12.8     ,2159.4     ,14.3  ,0
1302246779 ,2464.8 ,337.6     ,2120.4    ,5.7      ,2156.7     ,14.6  ,0
1302246789 ,2443.9 ,332.4     ,2107.8    ,2.9      ,2141.5     ,14.4  ,0
1302246799 ,2447.6 ,323.6     ,2119.8    ,2.8      ,2161.9     ,14.9  ,0
1302246809 ,2477.9 ,324       ,2150.7    ,1.7      ,2184.2     ,15.1  ,0
1302246819 ,2440.2 ,321.9     ,2114.1    ,3.1      ,2148       ,14.9  ,0.1
1302246829 ,2478   ,312.6     ,2162.4    ,2.4      ,2199.5     ,15    ,0
1302246839 ,2537.3 ,319.1     ,2214.6    ,2.3      ,2260.3     ,16.3  ,0
1302246849 ,2654.5 ,304.2     ,2348.1    ,1.3      ,2382.5     ,15.6  ,0
1302246859 ,2669.8 ,318.6     ,2347.8    ,2.9      ,2381.8     ,15.7  ,0
1302246869 ,2707.6 ,328.2     ,2375.8    ,2.8      ,2414.9     ,15.1  ,0
1302246879 ,2792.7 ,309.3     ,2480.5    ,1.8      ,2501.3     ,16.7  ,0
1302246889 ,2841.3 ,299.7     ,2532.7    ,7.8      ,2559.4     ,16.3  ,0
1302246899 ,2857.9 ,312.8     ,2531.7    ,12.5     ,2564.4     ,16.4  ,0
```
