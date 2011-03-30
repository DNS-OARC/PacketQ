/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 *                  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ##################################################################### 
 *
 */
#include "packetq.h"
#include "tcp.h"
#include "packet_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include "output.h"
#include "dns.h"
#include "icmp.h"

namespace se {

Payload g_payload;

Output g_output;
Str_conv converter;




int IP_header::decode(unsigned char * data,int itype, int i_id)
{
    ethertype = itype;
    id        = i_id;
    int len=0;
    // ether frame done (ignored mac's)
    // ip
    memset(&src_ip,0,sizeof(in6addr_t));
    memset(&dst_ip,0,sizeof(in6addr_t));
    int version = data[0]>>4;
    proto=0;
    if (version==4)
    {
        int header_len = (data[0]&0xf)*4;
        proto = data[9];
        src_ip.__in6_u.__u6_addr32[3] = get_int(&data[12]);
        dst_ip.__in6_u.__u6_addr32[3] = get_int(&data[16]);

        data += header_len;
        len  += header_len;
    }
    else if (version==6)
    {
        proto = data[6];
        src_ip.__in6_u.__u6_addr32[3] = get_int(&data[ 8]);
        src_ip.__in6_u.__u6_addr32[2] = get_int(&data[12]);
        src_ip.__in6_u.__u6_addr32[1] = get_int(&data[16]);
        src_ip.__in6_u.__u6_addr32[0] = get_int(&data[20]);

        dst_ip.__in6_u.__u6_addr32[3] = get_int(&data[24]);
        dst_ip.__in6_u.__u6_addr32[2] = get_int(&data[28]);
        dst_ip.__in6_u.__u6_addr32[1] = get_int(&data[32]);
        dst_ip.__in6_u.__u6_addr32[0] = get_int(&data[36]);

        data += 40;
        len  += 40;

        // process next headers - NOTE: there are 6 not 4
        while( proto == 0 || proto == 43 || proto == 44 || proto == 60 )
        {
            if (proto == 44)
            {
                return 0;
            }
            proto = data[0];
            int hdr_len = data[1]+8;
            data += hdr_len;
            len  += hdr_len;
        }
    }
    else
    {
        return 0;
    }

    return len;
}

void Packet::parse()
{
    unsigned char   *data = m_data;
    int len=m_len;
    if (len<14+5*4) return;  // check for etherframe size + ipv4 header

    int ethertype = data[13]|(data[12]<<8);
    data+=14;
    len-=14;

    int consumed = m_ip_header.decode( data, ethertype,m_id );
    m_ip_header.s			=m_s;
    m_ip_header.us			=m_us;
    data += consumed;
    len-= consumed;
    // tcp/udp
    int src_port=0;
    int dst_port=0;
    if (m_ip_header.proto==IPPROTO_TCP)
    {
        src_port = get_short(data);
        dst_port = get_short(&data[2]);
      

        int seq     = get_int(&data[4]);
        int ack     = get_int(&data[8]);

        int dataoffs   = 4*(data[12]>>4);

        unsigned char bits   = data[13];
        char syn     = ( bits >> 1 ) & 1;
        char fin     = ( bits >> 0 ) & 1;
        char rst     = ( bits >> 2 ) & 1;

        // get the assembled TCP packet and remove the individual segments.
        data += dataoffs;
        len += dataoffs;
        unsigned int rest=len;

        data = assemble_tcp (g_payload,&m_ip_header.src_ip, &m_ip_header.dst_ip, m_ip_header.src_port, m_ip_header.dst_port, &rest, seq, data, rest, syn, fin, rst, ack);
        len  = rest;
    }
    else if (m_ip_header.proto==IPPROTO_UDP)
    {
        src_port = get_short(data);
        dst_port = get_short(&data[2]);

        data+=8;
        len-=8;
    }
    m_ip_header.src_port	=src_port;
    m_ip_header.dst_port	=dst_port;

    if (data)
    {
        m_data = data;
        m_len  = len;
        parse_assembled();
    }

}

Parse_dns  *parse_dns    = 0;
Parse_icmp *parse_icmp   = 0;

bool init_packet_handler()
{
    parse_dns  = new Parse_dns();
    parse_icmp = new Parse_icmp();
}



void Packet::parse_assembled()
{

    if (parse_dns->parse(*this))
        ;
    else if (parse_icmp->parse(*this));

}

void IP_header_to_table::add_columns(Table &table)
{
    table.add_column("id",         Coltype::_int );
    table.add_column("s",          Coltype::_int ); 
    table.add_column("us",         Coltype::_int );
    table.add_column("ether_type", Coltype::_int );
    table.add_column("src_port",   Coltype::_int ); // this is really tcp/udp but accidents do happen
    table.add_column("dst_port",   Coltype::_int );
    table.add_column("src_addr",   Coltype::_text); // will start on a 64 bit boundary (put an even number of ints before this to avoid padding)
    table.add_column("dst_addr",   Coltype::_text);
    table.add_column("protocol",   Coltype::_int );

    acc_src_addr   = table.get_string_accessor("src_addr");
    acc_dst_addr   = table.get_string_accessor("dst_addr");
    acc_ether_type = table.get_int_accessor("ether_type");
    acc_protocol   = table.get_int_accessor("protocol");
    acc_src_port   = table.get_int_accessor("src_port");
    acc_dst_port   = table.get_int_accessor("dst_port");
    acc_s          = table.get_int_accessor("s");
    acc_us         = table.get_int_accessor("us");
    acc_id         = table.get_int_accessor("id");
}



void IP_header_to_table::assign(Row *row,IP_header *head)
{
    if (!row || !head)
        return;
    acc_id->set_i(             row, head->id);
    acc_s->set_i(             row, head->s);
    acc_us->set_i(            row, head->us);
    acc_ether_type->set_i(    row, head->ethertype);
    acc_protocol->set_i(      row, head->proto);
    acc_src_port->set_i(      row, head->src_port);
    acc_dst_port->set_i(      row, head->dst_port);
    if (head->ethertype==2048)
    {
        acc_src_addr->set_i(row, v4_addr2str(head->src_ip));
        acc_dst_addr->set_i(row, v4_addr2str(head->dst_ip));
    }
    else
    {
        acc_src_addr->set_i(row, v6_addr2str(head->src_ip));
        acc_dst_addr->set_i(row, v6_addr2str(head->dst_ip));
    }
}

const char *v4_addr2str(in6addr_t &addr)
{
    converter.reset();
    converter.add_attr_ipv4(addr.__in6_u.__u6_addr32[3]);
    return converter.get();
}
const char *v6_addr2str(in6addr_t &addr)
{
    converter.reset();
    converter.add_attr_ipv6(&addr.__in6_u.__u6_addr8[0]);
    return converter.get();
}
}
