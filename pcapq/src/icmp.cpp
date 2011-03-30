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
#include "output.h"
#include "icmp.h"
#include <stdlib.h>

namespace se {

bool Parse_icmp::parse(Packet &packet)
{
    if (packet.m_ip_header.proto != IPPROTO_ICMP)
        return false;
    if (packet.m_ip_header.ethertype != 2048) // we dont support ICMPv6 yet
        return false;
        
    Row *r = m_table->create_row();
    m_ip_helper.assign( r, &packet.m_ip_header );
    

    unsigned char *raw = packet.m_data;
    int type=raw[0];
    int code=raw[1];
    acc_type->set_i(r,type);
    acc_code->set_i(r,code);
    char desc[300];

    desc[0]=0;

    switch(type)
    {
        case(0):
            sprintf(desc,"Echo Reply");
            acc_echo_identifier->set_i( r,get_short(&raw[4]));
            acc_echo_sequence->set_i(   r,get_short(&raw[6]));
            //    acc_echo_sequence->set_i(   r,4);
            break;
        case(3):
            {
                const char *what="";
                const char *codes[]={"network ","host ","protocol ","port "};
                if (code<4)
                    what=codes[code];
                sprintf(desc,"Destination %sunreachable",what);
                IP_header head;
                head.decode(&raw[8],packet.m_ip_header.ethertype,0);
                acc_du_protocol->set_i(     r,head.proto);
                acc_du_src_addr->set_i(     r,v4_addr2str(head.src_ip));
                acc_du_dst_addr->set_i(     r,v4_addr2str(head.dst_ip));
            }
            break;
        case(4):
            sprintf(desc,"Source quench");
            break;
        case(5):
            sprintf(desc,"Redirect Message");
            break;
        case(6):
            sprintf(desc,"Alternate Host Address");
            break;
        case(8):
            sprintf(desc,"Echo Request");
            acc_echo_identifier->set_i( r,get_short(&raw[4]));
            acc_echo_sequence->set_i(   r,get_short(&raw[6]));
            break;
        case(9):
            sprintf(desc,"Router Advertisement");
            break;
        case(10):
            sprintf(desc,"Router Solicitation");
            break;
        case(11):
            sprintf(desc,"Time Exceeded");
            break;
        case(12):
            sprintf(desc,"Bad IP header");
            break;
        case(13):
            sprintf(desc,"Timestamp");
            break;
        case(14):
            sprintf(desc,"Timestamp Reply");
            break;
        case(15):
            sprintf(desc,"Information Request");
            break;
        case(16):
            sprintf(desc,"Information Reply");
            break;
        case(17):
            sprintf(desc,"Address Mask Request");
            break;
        case(18):
            sprintf(desc,"Address Mask Reply");
            break;
        case(30):
            sprintf(desc,"Traceroute");
            break;
    }
    

    acc_desc->set_i(     r,desc);

    return true;
}

void Parse_icmp::add_columns(Table &table)
{
    m_ip_helper.add_columns(table);

    table.add_column("type",            Coltype::_int );
    table.add_column("code",            Coltype::_int );
    table.add_column("echo_identifier", Coltype::_int );
    table.add_column("echo_sequence",   Coltype::_int );
    table.add_column("du_protocol",     Coltype::_int );
    table.add_column("du_src_addr",     Coltype::_text );
    table.add_column("du_dst_addr",     Coltype::_text );
    table.add_column("desc",            Coltype::_text );
}


void Parse_icmp::init_idx()
{
    m_table = g_db.create_table("icmp");
    if (!m_table)
        return;
    add_columns(*m_table);

    acc_type            = m_table->get_int_accessor("type");
    acc_code            = m_table->get_int_accessor("code");
    acc_echo_identifier = m_table->get_int_accessor("echo_identifier");
    acc_echo_sequence   = m_table->get_int_accessor("echo_sequence");
    acc_du_protocol     = m_table->get_int_accessor("du_protocol");
    acc_du_src_addr     = m_table->get_string_accessor("du_src_addr");
    acc_du_dst_addr     = m_table->get_string_accessor("du_dst_addr");
    acc_desc            = m_table->get_string_accessor("desc");
}

//void Parse_icmp::packet_insert(DNSMessage &message)
//{
//    DNSMessage::Header &header    = message.m_header;
//    IP_header          &ip_header = message.m_ip_header;
//
//    bool err=(message.m_error!=0); 
//    if (!header.qr)
//    {
//        if (header.qdcount==0)
//            err=true;
//    }
//
//    if (!err)
//    {
//        Row *r = g_app->m_dns->create_row();
//
//        acc_s->set_i(             r, ip_header.s);
//        acc_us->set_i(            r, ip_header.us);
//        acc_ether_type->set_i(    r, ip_header.ethertype);
//        acc_protocol->set_i(      r, ip_header.proto);
//        acc_src_port->set_i(      r, ip_header.src_port);
//        acc_msg_id->set_i(        r, header.id);
//
//        acc_qr->set_i(        r, header.qr);
//        acc_aa->set_i(        r, header.aa);
//        acc_tc->set_i(        r, header.tc);
//        acc_rd->set_i(        r, header.rd);
//        acc_cd->set_i(        r, header.cd);
//        acc_ra->set_i(        r, header.ra);
//        acc_ad->set_i(        r, header.ad);
//        acc_opcode->set_i(    r, header.opcode);
//        acc_rcode->set_i(     r, header.rcode);
//        if (message.m_edns0)
//        {
//            acc_edns0->set_i(             r, 1);
//            acc_do->set_i(                r, message.m_do);
//            acc_extended_rcode->set_i(    r, message.m_extended_rcode);
//            acc_version->set_i(           r, message.m_version);
//            acc_z->set_i(                 r, message.m_z);
//            acc_udp_size->set_i(          r, message.m_udp_size);
//        }
//        acc_qd_count->set_i(      r, header.qdcount);
//        acc_an_count->set_i(      r, header.ancount);
//        acc_ns_count->set_i(      r, header.nscount);
//        acc_ar_count->set_i(      r, header.arcount);
//        acc_qtype->set_i(         r, message.m_questions[0].qtype);
//        acc_qclass->set_i(        r, message.m_questions[0].qclass);
//        acc_qname->set_i(         r, message.m_questions[0].qname);
//        if (ip_header.ethertype==2048)
//        {
//            converter.reset();
//            converter.add_attr_ipv4(ip_header.src_ip->__in6_u.__u6_addr32[3]);
//            acc_src_addr->set_i(r, converter.get());
//            converter.reset();
//            converter.add_attr_ipv4(ip_header.dst_ip->__in6_u.__u6_addr32[3]);
//            acc_dst_addr->set_i(r, converter.get());
//        }
//        else
//        {
//            converter.reset();
//            converter.add_attr_ipv6(&ip_header.src_ip->__in6_u.__u6_addr8[0]);
//            acc_src_addr->set_i(r, converter.get());
//            converter.reset();
//            converter.add_attr_ipv6(&ip_header.dst_ip->__in6_u.__u6_addr8[0]);
//            acc_dst_addr->set_i(r, converter.get());
//        }
//        if (header.ancount)
//        {
//            acc_aname->set_i(  r, message.m_answer[0].name);
//            acc_atype->set_i(  r, message.m_answer[0].type);
//            acc_aclass->set_i( r, message.m_answer[0].rr_class);
//            acc_attl->set_i(   r, message.m_answer[0].ttl);
//        }
//        else
//        {
//            acc_aname->set_i(  r, "");
//            acc_atype->set_i(  r, 0);
//            acc_aclass->set_i( r, 0);
//            acc_attl->set_i(   r, 0);
//        }
//    }
//}


}
