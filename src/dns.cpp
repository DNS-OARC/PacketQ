/*
 Copyright (c) 2011, .SE - The Internet Infrastructure Foundation
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgement:
    This product includes software developed by the .SE - The Internet 
    Infrastructure Foundation.
 4. Neither the name of .SE - The Internet Infrastructure Foundation nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY .SE - THE INTERNET INFRASTRUCTURE FOUNDATION 
 ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL .SE - The Internet Infrastructure Foundation
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
 WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 OF SUCH DAMAGE.
 */
#include "packetq.h"
#include "tcp.h"
#include "packet_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <cctype>
#include "output.h"
#include "dns.h"

namespace se {

char visible_char_map[256];

void fill_in_visible_char_map()
{
    for (int i = 0; i < 256; ++i)
        visible_char_map[i] = isgraph(i) ? i : '$';
}

bool Parse_dns::parse(Packet &packet)
{
	if (12<=packet.m_len && (  packet.m_ip_header.proto == IPPROTO_UDP || packet.m_ip_header.proto == IPPROTO_TCP) )
	{
        if(g_app->sample_this())
        {
            unsigned char *ddata = packet.m_data;
            int            dlength = packet.m_len;
            if (packet.m_ip_header.proto == IPPROTO_TCP)
            {
                int dns_size = (int(ddata[0])<<8) | ddata[1];
                ddata+=2;
                dlength-=2;
                if (dns_size!=dlength)
                    return false;
            }
            DNSMessage message(ddata, dlength,packet.m_ip_header);
            return fill_in_row(message, packet.m_destination_row);
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
    table.add_column("msg_size",       Coltype::_int );
    table.add_column("opcode",         Coltype::_int );
    table.add_column("rcode",          Coltype::_int );
    table.add_column("extended_rcode", Coltype::_int ); 
    table.add_column("edns_version",   Coltype::_int );
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


    g_db.add_lut( "qtype", 1,   "A" );
    g_db.add_lut( "qtype", 2,   "NS" );
    g_db.add_lut( "qtype", 3,   "MD" );
    g_db.add_lut( "qtype", 4,   "MF" );
    g_db.add_lut( "qtype", 5,   "CNAME" );
    g_db.add_lut( "qtype", 6,   "SOA" );
    g_db.add_lut( "qtype", 7,   "MB" );
    g_db.add_lut( "qtype", 8,   "MG" );
    g_db.add_lut( "qtype", 9,   "MR" );
    g_db.add_lut( "qtype", 10,  "NULL" );
    g_db.add_lut( "qtype", 11,  "WKS" );
    g_db.add_lut( "qtype", 12,  "PTR" );
    g_db.add_lut( "qtype", 13,  "HINFO" );
    g_db.add_lut( "qtype", 14,  "MINFO" );
    g_db.add_lut( "qtype", 15,  "MX" );
    g_db.add_lut( "qtype", 16,  "TXT" );
    g_db.add_lut( "qtype", 17,  "RP" );
    g_db.add_lut( "qtype", 18,  "AFSDB" );
    g_db.add_lut( "qtype", 19,  "X25" );
    g_db.add_lut( "qtype", 20,  "ISDN" );
    g_db.add_lut( "qtype", 21,  "RT" );
    g_db.add_lut( "qtype", 22,  "NSAP" );
    g_db.add_lut( "qtype", 23,  "NSAP-PTR" );
    g_db.add_lut( "qtype", 24,  "SIG" );
    g_db.add_lut( "qtype", 25,  "KEY" );
    g_db.add_lut( "qtype", 26,  "PX" );
    g_db.add_lut( "qtype", 27,  "GPOS" );
    g_db.add_lut( "qtype", 28,  "AAAA" );
    g_db.add_lut( "qtype", 29,  "LOC" );
    g_db.add_lut( "qtype", 30,  "NXT" );
    g_db.add_lut( "qtype", 31,  "EID" );
    g_db.add_lut( "qtype", 32,  "NIMLOC" );
    g_db.add_lut( "qtype", 33,  "SRV" );
    g_db.add_lut( "qtype", 34,  "ATMA" );
    g_db.add_lut( "qtype", 35,  "NAPTR" );
    g_db.add_lut( "qtype", 36,  "KX" );
    g_db.add_lut( "qtype", 37,  "CERT" );
    g_db.add_lut( "qtype", 38,  "A6" );
    g_db.add_lut( "qtype", 39,  "DNAME" );
    g_db.add_lut( "qtype", 40,  "SINK" );
    g_db.add_lut( "qtype", 41,  "OPT" );
    g_db.add_lut( "qtype", 42,  "APL" );
    g_db.add_lut( "qtype", 43,  "DS" );
    g_db.add_lut( "qtype", 44,  "SSHFP" );
    g_db.add_lut( "qtype", 45,  "IPSECKEY" );
    g_db.add_lut( "qtype", 46,  "RRSIG" );
    g_db.add_lut( "qtype", 47,  "NSEC" );
    g_db.add_lut( "qtype", 48,  "DNSKEY" );
    g_db.add_lut( "qtype", 49,  "DHCID" );
    g_db.add_lut( "qtype", 50,  "NSEC3" );
    g_db.add_lut( "qtype", 51,  "NSEC3PARAM" );
    g_db.add_lut( "qtype", 55,  "HIP" );
    g_db.add_lut( "qtype", 56,  "NINFO" );
    g_db.add_lut( "qtype", 57,  "RKEY" );
    g_db.add_lut( "qtype", 58,  "TALINK" );
    g_db.add_lut( "qtype", 99,  "SPF" );
    g_db.add_lut( "qtype", 100, "UINFO" );
    g_db.add_lut( "qtype", 101, "UID" );
    g_db.add_lut( "qtype", 102, "GID" );
    g_db.add_lut( "qtype", 103, "UNSPEC" );
    g_db.add_lut( "qtype", 249, "TKEY" );
    g_db.add_lut( "qtype", 250, "TSIG" );
    g_db.add_lut( "qtype", 251, "IXFR" );
    g_db.add_lut( "qtype", 252, "AXFR" );
    g_db.add_lut( "qtype", 253, "MAILB" );
    g_db.add_lut( "qtype", 254, "MAILA" );
    g_db.add_lut( "qtype", 255, "*" );
    g_db.add_lut( "qtype", 256, "URI" );
    g_db.add_lut( "qtype", 32768, "TA" );
    g_db.add_lut( "qtype", 32769, "DLV" );

    g_db.add_lut( "rcode", 0  ,"NoError" );
    g_db.add_lut( "rcode", 1  ,"FormErr" );
    g_db.add_lut( "rcode", 2  ,"ServFail" );
    g_db.add_lut( "rcode", 3  ,"NXDomain" );
    g_db.add_lut( "rcode", 4  ,"NotImp" );
    g_db.add_lut( "rcode", 5  ,"Refused" );
    g_db.add_lut( "rcode", 6  ,"YXDomain" );
    g_db.add_lut( "rcode", 7  ,"YXRRSet" );
    g_db.add_lut( "rcode", 8  ,"NXRRSet" );
    g_db.add_lut( "rcode", 9  ,"NotAuth" );
    g_db.add_lut( "rcode", 10 ,"NotZone" );
    g_db.add_lut( "rcode", 16 ,"BADVERS" );
    g_db.add_lut( "rcode", 16 ,"BADSIG" );
    g_db.add_lut( "rcode", 17 ,"BADKEY" );
    g_db.add_lut( "rcode", 18 ,"BADTIME" );
    g_db.add_lut( "rcode", 19 ,"BADMODE" );
    g_db.add_lut( "rcode", 20 ,"BADNAME" );
    g_db.add_lut( "rcode", 21 ,"BADALG" );
    g_db.add_lut( "rcode", 22 ,"BADTRUNC" );


}

void Parse_dns::init()
{
    fill_in_visible_char_map();

    // create table
    m_table = g_db.create_table("dns");
    if (!m_table)
        return;
    add_columns(*m_table);

    acc_msg_id         = m_table->get_int_accessor("msg_id");
    acc_msg_size       = m_table->get_int_accessor("msg_size");
    acc_opcode         = m_table->get_int_accessor("opcode");
    acc_rcode          = m_table->get_int_accessor("rcode");
    acc_extended_rcode = m_table->get_int_accessor("extended_rcode");
    acc_edns_version   = m_table->get_int_accessor("edns_version");
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

bool Parse_dns::fill_in_row(DNSMessage &message, Row &destination_row)
{
    DNSMessage::Header &header    = message.m_header;
    IP_header          &ip_header = message.m_ip_header;

    if(message.m_error!=0)
        return false;

    if (!header.qr)
    {
        if (header.qdcount==0)
            return false;
    }

    Row *r = &destination_row;
    m_ip_helper.assign( r, &ip_header );

    acc_msg_id->set_i(    r, header.id);
    acc_msg_size->set_i(  r, message.m_length);
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
        acc_edns_version->set_i(      r, message.m_edns_version);
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
