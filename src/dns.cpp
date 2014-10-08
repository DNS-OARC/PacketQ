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
#include <sstream>

namespace se {

char visible_char_map[256];

void fill_in_visible_char_map()
{
    for (int i = 0; i < 256; ++i)
        visible_char_map[i] = isgraph(i) ? i : '$';
}

Parse_dns::Parse_dns()
{
    fill_in_visible_char_map();

    table_name = "dns";

    add_packet_columns();
    add_lookup_tables();
}

void Parse_dns::add_packet_columns()
{
    m_ip_helper.add_packet_columns(*this);

    add_packet_column("qname",          "", Coltype::_text, COLUMN_QNAME);
    add_packet_column("aname",          "", Coltype::_text, COLUMN_ANAME);
    add_packet_column("answers",        "", Coltype::_text, COLUMN_ANSWERS);
    add_packet_column("authorities",    "", Coltype::_text, COLUMN_AUTHORITIES);
    add_packet_column("additionals",    "", Coltype::_text, COLUMN_ADDITIONALS);
    add_packet_column("msg_id",         "", Coltype::_int, COLUMN_MSG_ID);
    add_packet_column("msg_size",       "", Coltype::_int, COLUMN_MSG_SIZE);
    add_packet_column("opcode",         "", Coltype::_int, COLUMN_OPCODE);
    add_packet_column("rcode",          "", Coltype::_int, COLUMN_RCODE);
    add_packet_column("extended_rcode", "", Coltype::_int, COLUMN_EXTENDED_RCODE);
    add_packet_column("edns_version",   "", Coltype::_int, COLUMN_EDNS_VERSION);
    add_packet_column("z",              "", Coltype::_int, COLUMN_Z);
    add_packet_column("udp_size",       "", Coltype::_int, COLUMN_UDP_SIZE);
    add_packet_column("qd_count",       "", Coltype::_int, COLUMN_QD_COUNT);
    add_packet_column("an_count",       "", Coltype::_int, COLUMN_AN_COUNT);
    add_packet_column("ns_count",       "", Coltype::_int, COLUMN_NS_COUNT);
    add_packet_column("ar_count",       "", Coltype::_int, COLUMN_AR_COUNT);
    add_packet_column("qtype",          "", Coltype::_int, COLUMN_QTYPE);
    add_packet_column("qclass",         "", Coltype::_int, COLUMN_QCLASS);
    add_packet_column("atype",          "", Coltype::_int, COLUMN_ATYPE);
    add_packet_column("aclass",         "", Coltype::_int, COLUMN_ACLASS);
    add_packet_column("attl",           "", Coltype::_int, COLUMN_ATTL);
    add_packet_column("aa",             "", Coltype::_bool, COLUMN_AA);
    add_packet_column("tc",             "", Coltype::_bool, COLUMN_TC);
    add_packet_column("rd",             "", Coltype::_bool, COLUMN_RD);
    add_packet_column("cd",             "", Coltype::_bool, COLUMN_CD);
    add_packet_column("ra",             "", Coltype::_bool, COLUMN_RA);
    add_packet_column("ad",             "", Coltype::_bool, COLUMN_AD);
    add_packet_column("do",             "", Coltype::_bool, COLUMN_DO);
    add_packet_column("edns0",          "", Coltype::_bool, COLUMN_EDNS0);
    add_packet_column("qr",             "", Coltype::_bool, COLUMN_QR);
}

void Parse_dns::add_lookup_tables()
{
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

    g_db.add_lut( "qclass", 1,   "IN" );
    g_db.add_lut( "qclass", 3,   "CH" );
    g_db.add_lut( "qclass", 4,   "HS" );
    g_db.add_lut( "qclass", 254, "NONE" );
    g_db.add_lut( "qclass", 255, "ANY" );
}

void Parse_dns::on_table_created(Table *table, const std::vector<int> &columns)
{
    m_ip_helper.on_table_created(table, columns);

    acc_msg_id         = table->get_accessor<int_column>("msg_id");
    acc_msg_size       = table->get_accessor<int_column>("msg_size");
    acc_opcode         = table->get_accessor<int_column>("opcode");
    acc_rcode          = table->get_accessor<int_column>("rcode");
    acc_extended_rcode = table->get_accessor<int_column>("extended_rcode");
    acc_edns_version   = table->get_accessor<int_column>("edns_version");
    acc_z              = table->get_accessor<int_column>("z");
    acc_udp_size       = table->get_accessor<int_column>("udp_size");
    acc_qd_count       = table->get_accessor<int_column>("qd_count");
    acc_an_count       = table->get_accessor<int_column>("an_count");
    acc_ns_count       = table->get_accessor<int_column>("ns_count");
    acc_ar_count       = table->get_accessor<int_column>("ar_count");
    acc_qtype          = table->get_accessor<int_column>("qtype");
    acc_qclass         = table->get_accessor<int_column>("qclass");
    acc_atype          = table->get_accessor<int_column>("atype");
    acc_aclass         = table->get_accessor<int_column>("aclass");
    acc_attl           = table->get_accessor<int_column>("attl");

    acc_qr             = table->get_accessor<bool_column>("qr");
    acc_aa             = table->get_accessor<bool_column>("aa");
    acc_tc             = table->get_accessor<bool_column>("tc");
    acc_rd             = table->get_accessor<bool_column>("rd");
    acc_cd             = table->get_accessor<bool_column>("cd");
    acc_ra             = table->get_accessor<bool_column>("ra");
    acc_ad             = table->get_accessor<bool_column>("ad");
    acc_do             = table->get_accessor<bool_column>("do");
    acc_edns0          = table->get_accessor<bool_column>("edns0");

    acc_qname          = table->get_accessor<text_column>("qname");
    acc_aname          = table->get_accessor<text_column>("aname");
    acc_answers        = table->get_accessor<text_column>("answers");
    acc_authorities    = table->get_accessor<text_column>("authorities");
    acc_additionals    = table->get_accessor<text_column>("additionals");
}

#define SSTR(x) dynamic_cast<std::ostringstream &>((std::ostringstream() << std::dec << x)).str()
RefCountString* Parse_dns::get_rrs(DNSMessage::Header &header, int count, DNSMessage::RR* rrs)
{
    std::string tmp;
    for (int i=0;i<(count < MAX_RRS ? count : MAX_RRS);i++) {
        if (i > 0) {
            tmp.append(",");
        }
        tmp.append(rrs[i].name);
        tmp.append(" ");
        tmp.append(SSTR(rrs[i].ttl));
        tmp.append(" ");
        RefCountString* h = g_db.get_value("qclass",rrs[i].rr_class);
        h ? tmp.append(h->data) : tmp.append(SSTR(rrs[i].rr_class));
        tmp.append(" ");
        h = g_db.get_value("qtype",rrs[i].type);
        h ? tmp.append(h->data) : tmp.append(SSTR(rrs[i].type));
    }
    return RefCountString::construct(tmp.c_str());
}

Packet::ParseResult Parse_dns::parse(Packet &packet, const std::vector<int> &columns, Row &destination_row, bool sample)
{
    if (not (packet.m_len >= 12 && (packet.m_ip_header.proto == IPPROTO_UDP || packet.m_ip_header.proto == IPPROTO_TCP)))
        return Packet::ERROR;

    if (!sample)
        return Packet::NOT_SAMPLED;

    unsigned char *ddata = packet.m_data;
    int            dlength = packet.m_len;

    if (packet.m_ip_header.proto == IPPROTO_TCP)
    {
        int dns_size = (int(ddata[0])<<8) | ddata[1];
        ddata+=2;
        dlength-=2;
        if (dns_size!=dlength)
            return Packet::ERROR;
    }

    DNSMessage message(ddata, dlength, packet.m_ip_header);

    DNSMessage::Header &header    = message.m_header;
    IP_header          &ip_header = message.m_ip_header;

    if (message.m_error!=0)
        return Packet::ERROR;

    if (!header.qr and header.qdcount==0)
        return Packet::ERROR;

    Row *r = &destination_row;

    m_ip_helper.assign(r, &ip_header, columns);

    for (auto i = columns.begin(), end = columns.end(); i != end; ++i) {
        switch (*i) {
        case COLUMN_MSG_ID:
            acc_msg_id.value(r) = header.id;
            break;

        case COLUMN_MSG_SIZE:
            acc_msg_size.value(r) = message.m_length;
            break;

        case COLUMN_QR:
            acc_qr.value(r) = header.qr;
            break;

        case COLUMN_AA:
            acc_aa.value(r) = header.aa;
            break;

        case COLUMN_TC:
            acc_tc.value(r) = header.tc;
            break;

        case COLUMN_RD:
            acc_rd.value(r) = header.rd;
            break;

        case COLUMN_CD:
            acc_cd.value(r) = header.cd;
            break;

        case COLUMN_RA:
            acc_ra.value(r) = header.ra;
            break;

        case COLUMN_AD:
            acc_ad.value(r) = header.ad;
            break;

        case COLUMN_OPCODE:
            acc_opcode.value(r) = header.opcode;
            break;

        case COLUMN_RCODE:
            acc_rcode.value(r) = header.rcode;
            break;

        case COLUMN_QD_COUNT:
            acc_qd_count.value(r) = header.qdcount;
            break;

        case COLUMN_AN_COUNT:
            acc_an_count.value(r) = header.ancount;
            break;

        case COLUMN_NS_COUNT:
            acc_ns_count.value(r) = header.nscount;
            break;

        case COLUMN_AR_COUNT:
            acc_ar_count.value(r) = header.arcount;
            break;

        case COLUMN_QTYPE:
            acc_qtype.value(r) = message.m_questions[0].qtype;
            break;

        case COLUMN_QCLASS:
            acc_qclass.value(r) = message.m_questions[0].qclass;
            break;

        case COLUMN_QNAME:
            acc_qname.value(r) = RefCountString::construct(message.m_questions[0].qname);
            break;

        case COLUMN_EDNS0:
            acc_edns0.value(r) = message.m_edns0 ? 1 : 0;
            break;

        case COLUMN_DO:
            acc_do.value(r) = message.m_edns0 ? message.m_do : 0;
            break;

        case COLUMN_EXTENDED_RCODE:
            acc_extended_rcode.value(r) = message.m_edns0 ? message.m_extended_rcode : 0;
            break;

        case COLUMN_EDNS_VERSION:
            acc_edns_version.value(r) = message.m_edns0 ? message.m_edns_version : 0;
            break;

        case COLUMN_Z:
            acc_z.value(r) = message.m_edns0 ? message.m_z : 0;
            break;

        case COLUMN_UDP_SIZE:
            acc_udp_size.value(r) = message.m_edns0 ? message.m_udp_size : 0;
            break;

        case COLUMN_ANSWERS:
            acc_answers.value(r) = get_rrs(header, header.ancount, message.m_answer);
            break;
         
        case COLUMN_AUTHORITIES:
            acc_authorities.value(r) = get_rrs(header, header.nscount, message.m_authority);
            break;
         
        case COLUMN_ADDITIONALS:
            acc_additionals.value(r) = get_rrs(header, header.arcount, message.m_additional);
            break;
         
        case COLUMN_ANAME:
            acc_aname.value(r) = header.ancount ? RefCountString::construct(message.m_answer[0].name) : RefCountString::construct("");
            break;

        case COLUMN_ATYPE:
            acc_atype.value(r) = header.ancount ? message.m_answer[0].type : 0;
            break;

        case COLUMN_ACLASS:
            acc_aclass.value(r) = header.ancount ? message.m_answer[0].rr_class : 0;
            break;

        case COLUMN_ATTL:
            acc_attl.value(r) = header.ancount ? message.m_answer[0].ttl : 0;
            break;
        }
    }

    return Packet::OK;
}

}
