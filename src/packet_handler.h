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

#define IPPROTO_ICMP 1

namespace se {

class Table;
class Row;
class Int_accessor;
class String_accessor;

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

const char *v4_addr2str(in6addr_t &addr);
const char *v6_addr2str(in6addr_t &addr);


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

class IP_header_to_table
{
public:
    IP_header_to_table()
    {
        acc_id         =0;
        acc_s          =0;
        acc_us         =0;
        acc_ether_type =0;
        acc_protocol   =0;
        acc_ip_ttl     =0;
        acc_src_port   =0;
        acc_dst_port   =0;
        acc_src_addr   =0;
        acc_dst_addr   =0;
        acc_fragments  =0;
    }

    void add_columns(Table &table);
    void assign(Row *row, IP_header *head);

private:
    Int_accessor *acc_id;
    Int_accessor *acc_s;
    Int_accessor *acc_us;
    Int_accessor *acc_ether_type;
    Int_accessor *acc_protocol;
    Int_accessor *acc_ip_ttl;
    Int_accessor *acc_src_port;
    Int_accessor *acc_dst_port;
    Int_accessor *acc_fragments;
    String_accessor *acc_src_addr;
    String_accessor *acc_dst_addr;
};

class Packet
{
    public:
    Packet(unsigned char *data,int len,int s, int us, int id, int link_layer_type, const std::string &application_protocol, Row &destination_row)
        : m_application_protocol(application_protocol), m_destination_row(destination_row)
    {
        m_s    = s;
        m_us   = us;
        m_data = data;
        m_len  = len;
        m_id   = id;
        m_link_layer_type   = link_layer_type;
    }
    bool parse();
    bool parse_ethernet();
    bool parse_ip(unsigned char *data, int len, int ether_type);
    bool parse_transport(unsigned char *data, int len);
    bool parse_application();
    IP_header       m_ip_header;
    unsigned char  *m_data;
    int             m_len;
    int             m_s;
    int             m_us;
    int             m_id;
    int             m_link_layer_type;
    const std::string &m_application_protocol;
    Row &m_destination_row;
};

class Packet_handler
{
    public:
    Packet_handler()
    {
    }
    const char *table_name() const;
    virtual void add_columns(Table &table)=0;
    virtual bool parse(Packet &packet)=0;
};

void init_packet_handler();
}
#endif

