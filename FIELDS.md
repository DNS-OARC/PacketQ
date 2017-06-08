# Fields

These are the current available fields you can do queries from on
the dns table, presented as JSON identifiers.

```javascript
[
  {
      { "name": "id","type": "int" },
      { "name": "s","type": "int" },
      { "name": "us","type": "int" },
      { "name": "ether_type","type": "int" },
      { "name": "src_port","type": "int" },
      { "name": "dst_port","type": "int" },
      { "name": "src_addr","type": "text" },
      { "name": "dst_addr","type": "text" },
      { "name": "protocol","type": "int" },
      { "name": "ip_ttl","type": "int" },
      { "name": "ip_version","type": "int" },
      { "name": "fragments","type": "int" },
      { "name": "qname","type": "text" },
      { "name": "aname","type": "text" },
      { "name": "msg_id","type": "int" },
      { "name": "msg_size","type": "int" },
      { "name": "opcode","type": "int" },
      { "name": "rcode","type": "int" },
      { "name": "extended_rcode","type": "int" },
      { "name": "edns_version","type": "int" },
      { "name": "z","type": "int" },
      { "name": "udp_size","type": "int" },
      { "name": "qd_count","type": "int" },
      { "name": "an_count","type": "int" },
      { "name": "ns_count","type": "int" },
      { "name": "ar_count","type": "int" },
      { "name": "qtype","type": "int" },
      { "name": "qclass","type": "int" },
      { "name": "atype","type": "int" },
      { "name": "aclass","type": "int" },
      { "name": "attl","type": "int" },
      { "name": "aa","type": "bool" },
      { "name": "tc","type": "bool" },
      { "name": "rd","type": "bool" },
      { "name": "cd","type": "bool" },
      { "name": "ra","type": "bool" },
      { "name": "ad","type": "bool" },
      { "name": "do","type": "bool" },
      { "name": "edns0","type": "bool" },
      { "name": "qr","type": "bool" },
      { "name": "edns0_ecs","type": "bool" },
      { "name": "edns0_ecs_family","type": "int" },
      { "name": "edns0_ecs_source","type": "int" },
      { "name": "edns0_ecs_scope","type": "int" },
      { "name": "edns0_ecs_address","type": "text" }
  }
]
```
