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
#include "output.h"
#include "dns.h"
#include "icmp.h"
#include "sql.h"

namespace se {

Payload g_payload;

Output g_output;
Str_conv converter;

class Fragments
{
public:
    class Range
    {
        public:
            bool operator < (const Range &r) const
            {
                if (begin<r.begin)
                    return true;
                return false;
            }
            Range(int s,int e1)
            {
                begin = s;
                endp1 = e1;
            }
            int begin;
            int endp1;
    };
    Fragments(const Fragments &f)
    {
//        printf( "copy Fragments\n" );
        m_first = f.m_first;
        m_complete = f.m_complete;
        m_frags = f.m_frags;
    }
    Fragments()
    {
        m_complete = 0;
        m_frags    = 0;
    }
    ~Fragments()
    {
//        printf( "delete Fragments\n", m_first.offset );
    }
    bool add(IP_header &head, unsigned char * data, int len)
    {
        if (head.offset==0)
            m_first = head;
        if (head.offset <0 || head.offset + len > 0x10000 || len <0 )
            return false;
        m_frags++;
        if(head.fragments == 0)
            m_complete = head.offset+len;
        bool complete = add_range(head.offset,head.offset + len);
        memcpy((void *)&m_buffer[head.offset], data, len);
        if(complete)
        {
            m_complete = head.offset+len;
            m_first.fragments = m_frags;
            return true;
        }
        return false;
    }
    bool add_range(int start, int end)
    {

        m_ranges.push_back(Range(start,end));
        m_ranges.sort();
        bool merged=true;
        // this is algorithmically horrid (hope there wont be tonnes of fragments)
        while(merged)
        {
            merged = false;
            std::list<Range>::iterator it = m_ranges.begin();
            std::list<Range>::iterator last = it;
            if (last == m_ranges.end())
                break;
            it++;
            for (; it != m_ranges.end(); it++)
            {
                if (last->endp1 == it->begin)
                {
                    merged = true;
                    last->endp1=it->endp1;
                    m_ranges.erase(it);
                    break;
                }
            }
        }
        if (m_ranges.size()==1 && m_ranges.begin()->endp1==m_complete && m_ranges.begin()->begin == 0)
            return true;
        return false;
            
    }

    std::list <Range> m_ranges;
    int               m_complete;
    int               m_frags;
    IP_header m_first;
    unsigned char m_buffer[0x10000];
};

class Ident
{
    public:
        bool operator < (const Ident &rhs) const
        {
            if(m_ident < rhs.m_ident)
                return true;
            if(m_ident > rhs.m_ident)
                return false;
            for (int i=0; i<4;i++)
            {
                if(m_src_ip.__in6_u.__u6_addr32[i] < rhs.m_src_ip.__in6_u.__u6_addr32[i])
                    return true;
                if(m_src_ip.__in6_u.__u6_addr32[i] > rhs.m_src_ip.__in6_u.__u6_addr32[i])
                    return false;
            }
            if(m_protocol < rhs.m_protocol)
                return true;
            if(m_protocol > rhs.m_protocol)
                return false;
            for (int i=0; i<4;i++)
            {
                if(m_dst_ip.__in6_u.__u6_addr32[i] < rhs.m_dst_ip.__in6_u.__u6_addr32[i])
                    return true;
                if(m_dst_ip.__in6_u.__u6_addr32[i] > rhs.m_dst_ip.__in6_u.__u6_addr32[i])
                    return false;
            }
            return false;
        }
        in6addr_t   m_dst_ip;
        in6addr_t   m_src_ip;
        int         m_ident;
        int         m_protocol;
};

class FragmentHandler
{
    public:
    void add_fragment(IP_header &head, unsigned char * data, int len,Packet &p)
    {
        Ident i;
        i.m_src_ip   = head.src_ip;
        i.m_dst_ip   = head.dst_ip;
        i.m_protocol = head.proto;
        i.m_ident    = head.ident;
        Fragments &frag = m_fragments[i];
        if( frag.add( head, data, len ) )
        {
            p.m_ip_header = frag.m_first;
            p.parse_transport(frag.m_buffer, frag.m_complete);
            m_fragments.erase(i);
        }
    }
    std::map< Ident, Fragments > m_fragments;
};

FragmentHandler m_fraghandler;

void IP_header::reset()
{
    memset(&src_ip,0,sizeof(in6addr_t));
    memset(&dst_ip,0,sizeof(in6addr_t));
    fragments = 0;
    offset    = 0;
    ident     = 0;
    s         = 0;
    us        = 0;
    ethertype = 0;
    src_port  = 0; 
    dst_port  = 0; 
    proto     = 0;
    ip_ttl    = 0;
    id        = 0; 
    length    = 0; 

}

int IP_header::decode(unsigned char * data,int itype, int i_id)
{
    reset();
    ethertype = itype;
    id        = i_id;
    int len=0;
    // ether frame done (ignored mac's)
    // ip

    int ip_version = data[0] >> 4;
    proto=0;
    if (ip_version==4)
    {
        if (ethertype==0)
            ethertype=0x800;
        int header_len = (data[0]&0xf)*4;
        proto = data[9];
	ip_ttl = data[8];
        src_ip.__in6_u.__u6_addr32[3] = get_int(&data[12]);
        dst_ip.__in6_u.__u6_addr32[3] = get_int(&data[16]);
        int totallen    = get_short(&data[2]);
        length          = totallen-header_len;    
        int flags       = get_short(&data[6]);
        offset          = (flags & 0x1fff)<<3;
        flags >>= 13;
        if (flags&1)
            fragments = 1;
        data += header_len;
        len  += header_len;
    }
    else if (ip_version==6)
    {
        if (ethertype==0)
            ethertype=0x86DD;
        proto = data[6];
	ip_ttl = data[7];
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
                offset    = get_short(&data[2]) & 0xfff8;
                fragments = get_short(&data[2]) & 1;
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

std::vector<Packet_handler *> packet_handlers;

Packet::ParseResult Packet::parse(Packet_handler *handler, const std::vector<int> &columns, Row &destination_row, bool sample)
{
    bool base_layers_parsed;
    if (m_link_layer_type == 1)
        base_layers_parsed = parse_ethernet();
    else
        base_layers_parsed = parse_ip(m_data, m_len, 0);

    if (!base_layers_parsed)
        return ERROR;

    // do the application layer
    return handler->parse(*this, columns, destination_row, sample);
}

bool Packet::parse_ethernet()
{
    unsigned char   *data = m_data;
    int len=m_len;
    if (len<14+5*4)
        return false;  // check for etherframe size + ipv4 header

    int ethertype = data[13]|(data[12]<<8);
    data+=14;
    len-=14;

    return parse_ip( data, len, ethertype );
}

bool Packet::parse_ip(unsigned char *data, int len, int ethertype)
{
    if (len<5*4)
        return false;  // check for etherframe size + ipv4 header

    int consumed   = m_ip_header.decode( data, ethertype,m_id );
    m_ip_header.s  = m_s;
    m_ip_header.us = m_us;
    data += consumed;
    len  -= consumed;
    if (m_ip_header.fragments > 0 || m_ip_header.offset > 0 )
    {
        m_fraghandler.add_fragment(m_ip_header, data, len, *this);
        return false;
    }

    return parse_transport(data, len);
}

bool Packet::parse_transport(unsigned char *data, int len)
{
    // tcp/udp
    if (m_ip_header.proto==IPPROTO_TCP)
    {
        m_ip_header.src_port = get_short(data);
        m_ip_header.dst_port = get_short(&data[2]);
      

        int seq     = get_int(&data[4]);
        int ack     = get_int(&data[8]);

        int dataoffs   = 4*(data[12]>>4);

        unsigned char bits   = data[13];
        char syn     = ( bits >> 1 ) & 1;
        char fin     = ( bits >> 0 ) & 1;
        char rst     = ( bits >> 2 ) & 1;

        // get the assembled TCP packet and remove the individual segments.
        data += dataoffs;
        len -= dataoffs;
        unsigned int rest=len;
        data = assemble_tcp (g_payload,&m_ip_header.src_ip, &m_ip_header.dst_ip, m_ip_header.src_port, m_ip_header.dst_port, &rest, seq, data, rest, syn, fin, rst, ack);
        len  = rest;
    }
    else if (m_ip_header.proto==IPPROTO_UDP)
    {
        m_ip_header.src_port = get_short(data);
        m_ip_header.dst_port = get_short(&data[2]);

        data+=8;
        len-=8;
    }

    if (data)
    {
        m_data = data;
        m_len  = len;
        return true;
    }

    return false;
}

Table *Packet_handler::create_table(const std::vector<int> &columns)
{
    Table *table = g_db.create_table(table_name);

    for (auto i = packet_columns.begin(); i != packet_columns.end(); ++i)
        if (std::find(columns.begin(), columns.end(), i->id) != columns.end())
            table->add_column(i->name, i->type, i->id);

    on_table_created(table, columns);

    return table;
}


void Packet_handler::add_packet_column(const char *name, const char *description, Coltype::Type type, int id)
{
    Packet_column c;
    c.name = name;
    c.description = description;
    c.id = id;
    c.type = type;
    packet_columns.push_back(c);
}


void init_packet_handlers()
{
    packet_handlers.push_back(new Parse_dns());
    packet_handlers.push_back(new Parse_icmp());
}

Packet_handler *get_packet_handler(std::string table_name)
{
    for (auto i = packet_handlers.begin(); i != packet_handlers.end(); ++i)
    {
        if (table_name == (*i)->table_name)
            return *i;
    }

    return 0;
}

void IP_header_to_table::add_packet_columns(Packet_handler &packet_handler)
{
    packet_handler.add_packet_column("id",         "ID", Coltype::_int, COLUMN_ID);
    packet_handler.add_packet_column("s",          "Seconds", Coltype::_int, COLUMN_S);
    packet_handler.add_packet_column("us",         "Milliseconds", Coltype::_int, COLUMN_US);
    packet_handler.add_packet_column("ether_type", "", Coltype::_int, COLUMN_ETHER_TYPE);
    packet_handler.add_packet_column("src_port",   "", Coltype::_int, COLUMN_SRC_PORT); // this is really tcp/udp but accidents do happen
    packet_handler.add_packet_column("dst_port",   "", Coltype::_int, COLUMN_DST_PORT);
    packet_handler.add_packet_column("src_addr",   "", Coltype::_text, COLUMN_SRC_ADDR); // will start on a 64 bit boundary (put an even number of ints before this to avoid padding)
    packet_handler.add_packet_column("dst_addr",   "", Coltype::_text, COLUMN_DST_ADDR);
    packet_handler.add_packet_column("protocol",   "", Coltype::_int, COLUMN_PROTOCOL);
    packet_handler.add_packet_column("ip_ttl",     "", Coltype::_int, COLUMN_IP_TTL);
    packet_handler.add_packet_column("fragments",  "", Coltype::_int, COLUMN_FRAGMENTS);
}

void IP_header_to_table::on_table_created(Table *table, const std::vector<int> &columns)
{
    acc_src_addr   = table->get_string_accessor("src_addr");
    acc_dst_addr   = table->get_string_accessor("dst_addr");
    acc_ether_type = table->get_int_accessor("ether_type");
    acc_protocol   = table->get_int_accessor("protocol");
    acc_ip_ttl     = table->get_int_accessor("ip_ttl");
    acc_src_port   = table->get_int_accessor("src_port");
    acc_dst_port   = table->get_int_accessor("dst_port");
    acc_s          = table->get_int_accessor("s");
    acc_us         = table->get_int_accessor("us");
    acc_id         = table->get_int_accessor("id");
    acc_fragments  = table->get_int_accessor("fragments");
}


void IP_header_to_table::assign(Row *row, IP_header *head, const std::vector<int> &columns)
{
    if (!head)
        return;

    for (auto i = columns.begin(), end = columns.end(); i != end; ++i) {
        switch (*i) {
        case COLUMN_ID:
            acc_id->set_i(row, head->id);
            break;

        case COLUMN_S:
            acc_s->set_i(row, head->s);
            break;

        case COLUMN_US:
            acc_us->set_i(row, head->us);
            break;

        case COLUMN_ETHER_TYPE:
            acc_ether_type->set_i(row, head->ethertype);
            break;

        case COLUMN_PROTOCOL:
            acc_protocol->set_i(row, head->proto);
            break;

        case COLUMN_IP_TTL:
            acc_ip_ttl->set_i(row, head->ip_ttl);
            break;

        case COLUMN_SRC_PORT:
            acc_src_port->set_i(row, head->src_port);
            break;

        case COLUMN_DST_PORT:
            acc_dst_port->set_i(row, head->dst_port);
            break;

        case COLUMN_FRAGMENTS:
            acc_fragments->set_i(row, head->fragments);
            break;

        case COLUMN_SRC_ADDR:
            if (head->ethertype==2048)
                acc_src_addr->set_i(row, v4_addr2str(head->src_ip));
            else
                acc_src_addr->set_i(row, v6_addr2str(head->src_ip));
            break;

        case COLUMN_DST_ADDR:
            if (head->ethertype==2048)
                acc_dst_addr->set_i(row, v4_addr2str(head->dst_ip));
            else
                acc_dst_addr->set_i(row, v6_addr2str(head->dst_ip));
            break;
        }
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
