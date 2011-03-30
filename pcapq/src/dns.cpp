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

namespace se {

bool Parse_dns::parse(Packet &packet)
{
	if (12<=packet.m_len && (  packet.m_ip_header.proto == IPPROTO_UDP || packet.m_ip_header.proto == IPPROTO_TCP) )
	{
        if(g_app->sample())
        {
            unsigned char *ddata = packet.m_data;
            int            dlength = packet.m_len;
            if (packet.m_ip_header.proto == IPPROTO_TCP)
            {
                ddata+=2;
                dlength-=2;
            }
            DNSMessage message(ddata, dlength,packet.m_ip_header);
            return packet_insert(message);
        }
	}
   return false; 
}

void Parse_dns::add_columns(Table &table)
{
    m_ip_helper.add_columns(table);

    table.add_column("qname",          Coltype::_text);
    table.add_column("aname",          Coltype::_text);
    table.add_column("msg_id",         Coltype::_int );
    table.add_column("opcode",         Coltype::_int );
    table.add_column("rcode",          Coltype::_int );
    table.add_column("extended_rcode", Coltype::_int ); 
    table.add_column("version",        Coltype::_int );
    table.add_column("z",              Coltype::_int );
    table.add_column("udp_size",       Coltype::_int );
    table.add_column("qd_count",       Coltype::_int );
    table.add_column("an_count",       Coltype::_int );
    table.add_column("ns_count",       Coltype::_int );
    table.add_column("ar_count",       Coltype::_int );
    table.add_column("qtype",          Coltype::_int );
    table.add_column("qclass",         Coltype::_int );
    table.add_column("atype",          Coltype::_int );
    table.add_column("aclass",         Coltype::_int );
    table.add_column("attl",           Coltype::_int );
    table.add_column("aa",             Coltype::_bool );
    table.add_column("tc",             Coltype::_bool );
    table.add_column("rd",             Coltype::_bool );
    table.add_column("cd",             Coltype::_bool );
    table.add_column("ra",             Coltype::_bool );
    table.add_column("ad",             Coltype::_bool );
    table.add_column("do",             Coltype::_bool );
    table.add_column("edns0",          Coltype::_bool );
    table.add_column("qr",             Coltype::_bool );
}

void Parse_dns::init()
{
    // create table
    m_table = g_db.create_table("dns");
    if (!m_table)
        return;
    add_columns(*m_table);

    acc_msg_id         = m_table->get_int_accessor("msg_id");
    acc_opcode         = m_table->get_int_accessor("opcode");
    acc_rcode          = m_table->get_int_accessor("rcode");
    acc_extended_rcode = m_table->get_int_accessor("extended_rcode");
    acc_version        = m_table->get_int_accessor("version");
    acc_z              = m_table->get_int_accessor("z");
    acc_udp_size       = m_table->get_int_accessor("udp_size");
    acc_qd_count       = m_table->get_int_accessor("qd_count");
    acc_an_count       = m_table->get_int_accessor("an_count");
    acc_ns_count       = m_table->get_int_accessor("ns_count");
    acc_ar_count       = m_table->get_int_accessor("ar_count");
    acc_qtype          = m_table->get_int_accessor("qtype");
    acc_qclass         = m_table->get_int_accessor("qclass");
    acc_atype          = m_table->get_int_accessor("atype");
    acc_aclass         = m_table->get_int_accessor("aclass");
    acc_attl           = m_table->get_int_accessor("attl");

    acc_qr             = m_table->get_bool_accessor("qr");
    acc_aa             = m_table->get_bool_accessor("aa");
    acc_tc             = m_table->get_bool_accessor("tc");
    acc_rd             = m_table->get_bool_accessor("rd");
    acc_cd             = m_table->get_bool_accessor("cd");
    acc_ra             = m_table->get_bool_accessor("ra");
    acc_ad             = m_table->get_bool_accessor("ad");
    acc_do             = m_table->get_bool_accessor("do");
    acc_edns0          = m_table->get_bool_accessor("edns0");

    acc_qname          = m_table->get_string_accessor("qname");
    acc_aname          = m_table->get_string_accessor("aname");
}

bool Parse_dns::packet_insert(DNSMessage &message)
{
    DNSMessage::Header &header    = message.m_header;
    IP_header          &ip_header = message.m_ip_header;

    bool err=(message.m_error!=0); 
    if (!header.qr)
    {
        if (header.qdcount==0)
            return false;
    }

    Row *r = m_table->create_row();
    m_ip_helper.assign( r, &ip_header );

    acc_msg_id->set_i(    r, header.id);
    acc_qr->set_i(        r, header.qr);
    acc_aa->set_i(        r, header.aa);
    acc_tc->set_i(        r, header.tc);
    acc_rd->set_i(        r, header.rd);
    acc_cd->set_i(        r, header.cd);
    acc_ra->set_i(        r, header.ra);
    acc_ad->set_i(        r, header.ad);
    acc_opcode->set_i(    r, header.opcode);
    acc_rcode->set_i(     r, header.rcode);
    acc_qd_count->set_i(  r, header.qdcount);
    acc_an_count->set_i(  r, header.ancount);
    acc_ns_count->set_i(  r, header.nscount);
    acc_ar_count->set_i(  r, header.arcount);
    acc_qtype->set_i(     r, message.m_questions[0].qtype);
    acc_qclass->set_i(    r, message.m_questions[0].qclass);
    acc_qname->set_i(     r, message.m_questions[0].qname);
    if (message.m_edns0)
    {
        acc_edns0->set_i(             r, 1);
        acc_do->set_i(                r, message.m_do);
        acc_extended_rcode->set_i(    r, message.m_extended_rcode);
        acc_version->set_i(           r, message.m_version);
        acc_z->set_i(                 r, message.m_z);
        acc_udp_size->set_i(          r, message.m_udp_size);
    }
    if (header.ancount)
    {
        acc_aname->set_i(  r, message.m_answer[0].name);
        acc_atype->set_i(  r, message.m_answer[0].type);
        acc_aclass->set_i( r, message.m_answer[0].rr_class);
        acc_attl->set_i(   r, message.m_answer[0].ttl);
    }
    else
    {
        acc_aname->set_i(  r, "");
        acc_atype->set_i(  r, 0);
        acc_aclass->set_i( r, 0);
        acc_attl->set_i(   r, 0);
    }
    return true;
}




}
