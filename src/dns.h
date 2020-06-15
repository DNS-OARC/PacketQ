/*
 * Copyright (c) 2017-2020, OARC, Inc.
 * Copyright (c) 2011-2017, IIS - The Internet Foundation in Sweden
 * All rights reserved.
 *
 * This file is part of PacketQ.
 *
 * PacketQ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PacketQ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PacketQ.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __packetq_dns_h
#define __packetq_dns_h

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "output.h"
#include "packet_handler.h"
#include "tcp.h"

#define IPPROTO_ICMP 1

namespace packetq {

extern char visible_char_map[256];

class DNSMessage {
public:
    class Header {
    public:
        int  id;
        int  z;
        bool qr;
        int  opcode;
        bool aa;
        bool tc;
        bool rd;
        bool ra;
        bool ad;
        bool cd;
        int  rcode;
        int  qdcount;
        int  ancount;
        int  nscount;
        int  arcount;
        Header()
            : z(0)
        {
            id      = 0;
            qr      = 0;
            opcode  = 0;
            aa      = 0;
            tc      = 0;
            rd      = 0;
            ra      = 0;
            ad      = 0;
            cd      = 0;
            rcode   = 0;
            qdcount = 0;
            ancount = 0;
            nscount = 0;
            arcount = 0;
        }
        void parse(DNSMessage& p)
        {
            /*
            From rfc 2929
                                          1  1  1  1  1  1
            0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      ID                       |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                QDCOUNT/ZOCOUNT                |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                ANCOUNT/PRCOUNT                |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                NSCOUNT/UPCOUNT                |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    ARCOUNT                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            */

            id      = p.get_ushort(0);
            qr      = p.get_bit(2, 0);
            opcode  = p.get_bits(2, 1, 4);
            aa      = p.get_bit(2, 5);
            tc      = p.get_bit(2, 6);
            rd      = p.get_bit(2, 7);
            ra      = p.get_bit(2, 8);
            ad      = p.get_bit(2, 10);
            cd      = p.get_bit(2, 11);
            rcode   = p.get_bits(2, 12, 4);
            qdcount = p.get_ushort(4);
            ancount = p.get_ushort(6);
            nscount = p.get_ushort(8);
            arcount = p.get_ushort(10);
        }
    };
    class Question {
    public:
        char qname[0x2000];
        int  qtype;
        int  qclass;

        Question()
        {
            qname[0] = 0;
            qtype    = 0;
            qclass   = 0;
        }

        int parse(DNSMessage& m, int offs)
        {
            offs  = m.parse_dname(qname, sizeof(qname), offs);
            qtype = m.get_ushort(offs);
            offs += 2;
            qclass = m.get_ushort(offs);
            offs += 2;
            return offs;
        }
    };

    class RR {
    public:
        char         name[0x2000];
        int          type;
        int          rr_class;
        unsigned int ttl;
        int          rdlength;
        int          doffs;

        RR()
        {
            name[0]  = 0;
            type     = 0;
            rr_class = 0;
            ttl      = 0;
            rdlength = 0;
            doffs    = 0;
        }

        int parse(DNSMessage& m, int offs)
        {
            offs = m.parse_dname(name, sizeof(name), offs);
            type = m.get_ushort(offs);
            if (type == 41) {
                m.m_opt_rr     = this;
                m.m_new_opt_rr = true;
            }
            offs += 2;
            rr_class = m.get_ushort(offs);
            offs += 2;
            ttl = m.get_ushort(offs) << 16;
            ttl |= m.get_ushort(offs + 2);
            offs += 4;
            rdlength = m.get_ushort(offs);
            offs += 2;
            doffs = offs;
            offs += rdlength;
            return offs;
        }
    };

    IP_header&     m_ip_header;
    unsigned char* m_data;
    int            m_length;
    Header         m_header;
    Question       m_questions[2];
    RR             m_answer[2];
    RR             m_authority[2];
    RR             m_additional[2];
    RR*            m_opt_rr;
    bool           m_new_opt_rr;
    int            m_error;
    bool           m_edns0;
    bool           m_do;
    int            m_extended_rcode;
    int            m_edns_version;
    int            m_z;
    int            m_udp_size;
    bool           m_edns0_ecs;
    int            m_edns0_ecs_family;
    int            m_edns0_ecs_source;
    int            m_edns0_ecs_scope;
    in6addr_t      m_edns0_ecs_addr;
    bool           m_edns0_ecs_addr_set;

    DNSMessage(unsigned char* data, int len, IP_header& head)
        : m_ip_header(head)
    {
        m_opt_rr             = 0;
        m_new_opt_rr         = false;
        m_error              = 0;
        m_data               = data;
        m_length             = len;
        m_edns0              = false;
        m_do                 = false;
        m_extended_rcode     = 0;
        m_edns_version       = 0;
        m_z                  = 0;
        m_udp_size           = 0;
        m_edns0_ecs          = false;
        m_edns0_ecs_family   = 0;
        m_edns0_ecs_source   = 0;
        m_edns0_ecs_scope    = 0;
        m_edns0_ecs_addr_set = false;

        parse();
    }
    int parse_dname(char* out, int size, int offs)
    {
        int p         = 0;
        int savedoffs = 0;
        int n         = get_ubyte(offs++);
        if (n == 0)
            out[p++] = '.';

        while (n > 0) {
            while (n >= 192) {
                if (savedoffs) {
                    out[p++] = 0;
                    return savedoffs;
                }
                savedoffs = offs + 1;
                int n2    = get_ubyte(offs++);
                int ptr   = (n & 63) * 0x100 + n2;
                offs      = ptr;
                n         = get_ubyte(offs++);
            }

            // if the string is too long restart and mess it up
            if (n + 20 + p > size / 2)
                p = 0;

            while (n-- > 0) {
                out[p++] = visible_char_map[get_ubyte(offs++)];
            }
            out[p++] = '.';
            n        = get_ubyte(offs++);
        }
        if (savedoffs)
            offs = savedoffs;
        out[p++] = 0;
        return offs;
    }
    void parse_opt_rr()
    {
        if (m_opt_rr) {
            if (!m_edns0) {
                m_edns0           = true;
                unsigned long ttl = m_opt_rr->ttl;
                m_do              = (ttl >> 15) & 1;
                m_extended_rcode  = ttl >> 24;
                m_edns_version    = (ttl >> 16) & 0xff;
                m_z               = ttl & 0x7fff;
                m_udp_size        = m_opt_rr->rr_class;
            }
            if (((m_opt_rr->ttl >> 16) & 0xff) == 0 && m_opt_rr->rdlength > 0) {
                // Parse this OPT RR that is EDNS0
                int rdlen  = m_opt_rr->rdlength,
                    offs   = m_opt_rr->doffs,
                    opcode = 0,
                    oplen  = 0;

                while (rdlen > 3) {
                    // Minimum op code and length
                    opcode = get_ushort(offs);
                    oplen  = get_ushort(offs + 2);
                    offs += 4;
                    rdlen -= 4;

                    if (rdlen < oplen)
                        break;

                    if (opcode == 8 && !m_edns0_ecs && oplen > 3) {
                        // ECS - Client Subnet - RFC7871
                        m_edns0_ecs        = true;
                        m_edns0_ecs_family = get_ushort(offs);
                        m_edns0_ecs_source = get_ubyte(offs + 2);
                        m_edns0_ecs_scope  = get_ubyte(offs + 3);

                        int addrlen = (m_edns0_ecs_source / 8) + (m_edns0_ecs_source % 8 ? 1 : 0);
                        int fill    = 0;

                        if (addrlen <= (oplen - 4)) {
                            switch (m_edns0_ecs_family) {
                            case 1:
                                fill                 = 4;
                                m_edns0_ecs_addr_set = true;
                                break;
                            case 2:
                                fill                 = 16;
                                m_edns0_ecs_addr_set = true;
                                break;
                            }

                            int a = 0, b;
                            for (b = 15; fill && b > -1; fill--, b--) {
                                if (a < addrlen) {
                                    m_edns0_ecs_addr.__in6_u.__u6_addr8[b] = get_ubyte(offs + 4 + a);
                                    a++;
                                } else {
                                    m_edns0_ecs_addr.__in6_u.__u6_addr8[b] = 0;
                                }
                            }
                        }
                    }

                    rdlen -= oplen;
                    offs += oplen;
                }
            }
        }
    }
    void parse()
    {
        m_header.parse(*this);
        int offs = 12;
        int q    = 0;
        int cnt  = m_header.qdcount;
        while (cnt-- > 0) {
            offs = m_questions[q].parse(*this, offs);
            if (offs > m_length) {
                m_questions[q].qname[0] = 0;
                m_error                 = offs;
                return;
            }
            q = 1; // not ++ ignore further Q's
        }
        q   = 0;
        cnt = m_header.ancount;
        while (cnt-- > 0) {
            offs = m_answer[q].parse(*this, offs);
            q    = 1; // not ++ ignore further Q's
            if (offs > m_length) {
                m_error = offs;
                return;
            }
        }
        q   = 0;
        cnt = m_header.nscount;
        while (cnt-- > 0) {
            offs = m_authority[q].parse(*this, offs);
            q    = 1; // not ++ ignore further Q's
            if (offs > m_length) {
                m_error = offs;
                return;
            }
        }
        q   = 0;
        cnt = m_header.arcount;
        while (cnt-- > 0) {
            offs = m_additional[q].parse(*this, offs);
            q    = 1; // not ++ ignore further Q's
            if (offs > m_length) {
                m_error = offs;
                return;
            }
            if (m_new_opt_rr) {
                parse_opt_rr();
                m_new_opt_rr = false;
            }
        }
        if (offs > m_length)
            m_error = offs;
    }

    unsigned int get_ubyte(int offs)
    {
        if (offs >= m_length)
            return 0;
        return int(m_data[offs]);
    }
    // returns 16 bit number at byte offset offs
    unsigned int get_ushort(int offs)
    {
        if ((offs + 1) >= m_length)
            return 0;
        return (int(m_data[offs]) << 8) | int(m_data[offs + 1]);
    }
    uint32_t get_uint32(int offs)
    {
        if ((offs + 3) >= m_length)
            return 0;
        return (uint32_t(m_data[offs]) << 24) | (uint32_t(m_data[offs + 1]) << 16) | (uint32_t(m_data[offs + 2]) << 8) | uint32_t(m_data[offs + 3]);
    }
    bool get_bit(int offs, int bit)
    {
        if (offs >= m_length)
            return 0;
        return ((get_ushort(offs) << bit) & 0x8000) == 0x8000;
    }
    unsigned int get_bits(int offs, int bit, int bits)
    {
        if (offs >= m_length)
            return 0;
        return ((get_ushort(offs) << bit) & 0xffff) >> (16 - bits);
    }
};

class Parse_dns : public Packet_handler {
public:
    enum {
        COLUMN_QNAME = IP_header_to_table::COLUMN_FRAGMENTS + 1,
        COLUMN_ANAME,
        COLUMN_MSG_ID,
        COLUMN_MSG_SIZE,
        COLUMN_OPCODE,
        COLUMN_RCODE,
        COLUMN_EXTENDED_RCODE,
        COLUMN_EDNS_VERSION,
        COLUMN_Z,
        COLUMN_UDP_SIZE,
        COLUMN_QD_COUNT,
        COLUMN_AN_COUNT,
        COLUMN_NS_COUNT,
        COLUMN_AR_COUNT,
        COLUMN_QTYPE,
        COLUMN_QCLASS,
        COLUMN_ATYPE,
        COLUMN_ACLASS,
        COLUMN_ATTL,
        COLUMN_AA,
        COLUMN_TC,
        COLUMN_RD,
        COLUMN_CD,
        COLUMN_RA,
        COLUMN_AD,
        COLUMN_DO,
        COLUMN_EDNS0,
        COLUMN_QR,
        COLUMN_EDNS0_ECS,
        COLUMN_EDNS0_ECS_FAMILY,
        COLUMN_EDNS0_ECS_SOURCE,
        COLUMN_EDNS0_ECS_SCOPE,
        COLUMN_EDNS0_ECS_ADDRESS,
    };

    Parse_dns();

    virtual void on_table_created(Table* table, const std::vector<int>& columns);
    virtual Packet::ParseResult parse(Packet& packet, const std::vector<int>& columns, Row& destination_row, bool sample);

    void add_packet_columns();
    void add_lookup_tables();

private:
    Str_conv converter;

    IP_header_to_table m_ip_helper;

    Int_accessor  acc_s;
    Int_accessor  acc_us;
    Int_accessor  acc_ether_type;
    Int_accessor  acc_protocol;
    Int_accessor  acc_src_port;
    Int_accessor  acc_msg_id;
    Int_accessor  acc_msg_size;
    Int_accessor  acc_opcode;
    Int_accessor  acc_rcode;
    Int_accessor  acc_extended_rcode;
    Int_accessor  acc_edns_version;
    Int_accessor  acc_z;
    Int_accessor  acc_udp_size;
    Int_accessor  acc_qd_count;
    Int_accessor  acc_an_count;
    Int_accessor  acc_ns_count;
    Int_accessor  acc_ar_count;
    Int_accessor  acc_qtype;
    Int_accessor  acc_qclass;
    Int_accessor  acc_atype;
    Int_accessor  acc_aclass;
    Int_accessor  acc_attl;
    Int_accessor  acc_edns0_ecs_family;
    Int_accessor  acc_edns0_ecs_source;
    Int_accessor  acc_edns0_ecs_scope;
    Bool_accessor acc_qr;
    Bool_accessor acc_aa;
    Bool_accessor acc_tc;
    Bool_accessor acc_rd;
    Bool_accessor acc_cd;
    Bool_accessor acc_ra;
    Bool_accessor acc_ad;
    Bool_accessor acc_do;
    Bool_accessor acc_edns0;
    Bool_accessor acc_edns0_ecs;
    Text_accessor acc_qname;
    Text_accessor acc_aname;
    Text_accessor acc_src_addr;
    Text_accessor acc_dst_addr;
    Text_accessor acc_edns0_ecs_address;
};

} // namespace packetq

#endif // __packetq_dns_h
