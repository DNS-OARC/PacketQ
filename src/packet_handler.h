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
#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcp.h"
#include <assert.h>
#include <cctype>
#include <string>
#include <vector>
#include "sql.h"

#define IPPROTO_ICMP 1

namespace se {

class Table;
class Row;

inline int get_int_h(unsigned char *data)
{
    return  data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24);
}

inline int get_short_h(unsigned char *data)
{
    return  data[0] | (data[1]<<8) ;
}

inline int get_int(unsigned char *data)
{
    return  data[3] | (data[2]<<8) | (data[1]<<16) | (data[0]<<24);
}

inline int get_short(unsigned char *data)
{
    return  data[1] | (data[0]<<8) ;
}

RefCountString *v4_addr2str(in6addr_t &addr);
RefCountString *v6_addr2str(in6addr_t &addr);


class Payload
{
    public:
        char  m_p[0x10000];
        int   m_size;
        Payload()
        {
            m_size=sizeof(m_p);
        }
        inline char *alloc(int size)
        {
            if (size>m_size)
                return 0;
            return m_p;
        }
};

class IP_header
{
public:
    void reset();
    int decode(unsigned char *data, int ether_type,int id); 
    unsigned int       s;
    unsigned int       us;
    unsigned short     ethertype;
    in6addr_t          src_ip; 
    in6addr_t          dst_ip;
    unsigned short     src_port; 
    unsigned short     dst_port; 
    unsigned short     proto;
    unsigned short     ip_ttl;
    unsigned int       id; 
    unsigned int       length; 
    unsigned int       fragments; 
    unsigned int       ident; 
    unsigned int       offset; 
};

class Packet_handler;

class IP_header_to_table
{
public:
    enum {
        COLUMN_ID,
        COLUMN_S,
        COLUMN_US,
        COLUMN_ETHER_TYPE,
        COLUMN_PROTOCOL,
        COLUMN_IP_TTL,
        COLUMN_SRC_PORT,
        COLUMN_DST_PORT,
        COLUMN_SRC_ADDR,
        COLUMN_DST_ADDR,
        COLUMN_FRAGMENTS
    };

    void add_packet_columns(Packet_handler &packet_handler);
    void on_table_created(Table *table, const std::vector<int> &columns);
    void assign(Row *row, IP_header *head, const std::vector<int> &columns);

private:
    Int_accessor acc_id;
    Int_accessor acc_s;
    Int_accessor acc_us;
    Int_accessor acc_ether_type;
    Int_accessor acc_protocol;
    Int_accessor acc_ip_ttl;
    Int_accessor acc_src_port;
    Int_accessor acc_dst_port;
    Int_accessor acc_fragments;
    Text_accessor acc_src_addr;
    Text_accessor acc_dst_addr;
};

class Packet
{
public:
    enum ParseResult {
        ERROR, OK, NOT_SAMPLED
    };

    Packet(unsigned char *data,int len,int s, int us, int id, int link_layer_type)
    {
        m_s    = s;
        m_us   = us;
        m_data = data;
        m_len  = len;
        m_id   = id;
        m_link_layer_type   = link_layer_type;
    }

    ParseResult parse(Packet_handler *handler, const std::vector<int> &columns, Row &destination_row, bool sample);
    bool parse_ethernet();
    bool parse_ip(unsigned char *data, int len, int ether_type);
    bool parse_transport(unsigned char *data, int len);

    IP_header       m_ip_header;
    unsigned char  *m_data;
    int             m_len;
    int             m_s;
    int             m_us;
    int             m_id;
    int             m_link_layer_type;
};

struct Packet_column
{
    const char *name;
    const char *description;
    int id;
    Coltype::Type type;
};

class Packet_handler
{
public:
    Packet_handler()
    {
    }
    virtual ~Packet_handler()
    {
    }

    Table *create_table(const std::vector<int> &columns);

    // for actual packet handlers to fill in
    virtual void on_table_created(Table *table, const std::vector<int> &columns) = 0;
    virtual Packet::ParseResult parse(Packet &packet, const std::vector<int> &columns, Row &destination_row, bool sample) = 0;

    const char *table_name;
    std::vector<Packet_column> packet_columns;

    void add_packet_column(const char *name, const char *description, Coltype::Type type, int id);
};

void init_packet_handlers();
void destroy_packet_handlers();
Packet_handler *get_packet_handler(std::string table_name);

}
#endif

