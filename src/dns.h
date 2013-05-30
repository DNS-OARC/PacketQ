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
#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcp.h"
#include "packet_handler.h"
#include <assert.h>

#define IPPROTO_ICMP 1

namespace se {

extern char visible_char_map[256];

class DNSMessage
{
    public:
        class Header
        {
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
                {
                    id=0;          
                    qr=0;
                    opcode=0;
                    aa=0;
                    tc=0;
                    rd=0;
                    ra=0;
                    ad=0;
                    cd=0;
                    rcode=0;
                    qdcount=0;
                    ancount=0;
                    nscount=0;
                    arcount=0;
                }
                void parse(DNSMessage &p)
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
                    qr      = p.get_bit(2,0);
                    opcode  = p.get_bits(2,1,4);
                    aa      = p.get_bit(2,5);
                    tc      = p.get_bit(2,6);
                    rd      = p.get_bit(2,7);
                    ra      = p.get_bit(2,8);
                    ad      = p.get_bit(2,10);
                    cd      = p.get_bit(2,11);
                    rcode   = p.get_bits(2,12,4);
                    qdcount = p.get_ushort(4);
                    ancount = p.get_ushort(6);
                    nscount = p.get_ushort(8);
                    arcount = p.get_ushort(10);

                }
        };
        class Question
        {
            public:
            char qname[0x2000];
            int  qtype;
            int  qclass;
            int parse(DNSMessage &m,int offs)
            {
                offs     =  m.parse_dname(qname,sizeof(qname),offs);
                qtype    =  m.get_ushort(offs);
                offs     += 2;
                qclass   =  m.get_ushort(offs);
                offs     += 2;
                return offs;
            }
        };

        class RR
        {
            public:
                char name[0x2000];
                int  type;
                int  rr_class;
                unsigned int ttl;
                int rdlength;
                int doffs;

            int parse(DNSMessage &m,int offs)
            {
                offs=m.parse_dname(name,sizeof(name),offs);
                type=m.get_ushort(offs);
                if (type==41)
                    m.m_opt_rr=this;
                offs+=2;
                rr_class=m.get_ushort(offs);
                offs+=2;
                ttl=m.get_ushort(offs)<<16;
                ttl|=m.get_ushort(offs+2);
                offs+=4;
                rdlength=m.get_ushort(offs);
                offs+=2;
                doffs=offs;
                offs+=rdlength;
                return offs;
            }
        };

        IP_header        &m_ip_header;
        unsigned char    *m_data;
        int              m_length;
        Header           m_header;
        Question         m_questions[2];
        RR               m_answer[2];
        RR               m_authority[2];
        RR               m_additional[2];
        RR               *m_opt_rr;
        int              m_error;
        bool             m_edns0;
        bool             m_do;
        int              m_extended_rcode;
        int              m_edns_version;
        int              m_z;
        int              m_udp_size;


        DNSMessage(unsigned char *data,int len,IP_header &head): m_ip_header(head)
        {
            m_opt_rr        = 0;
            m_error         = 0;
            m_data          = data;
            m_length        = len;
            m_edns0         = false;
            m_do            = false;
            m_extended_rcode= 0;
            m_edns_version  = 0;
            m_z             = 0;
            m_udp_size      = 0;

            parse();
        }
        int parse_dname(char *out,int size,int offs)
        {
            int p=0;
            int savedoffs=0;
            int n=get_ubyte(offs++);
            if (n==0)
                out[p++]='.';

            while(n>0)
            {
                while(n>=192)
                {
                    if (savedoffs)
                    {
                        out[p++]=0;
                        return savedoffs;
                    }
                    savedoffs=offs+1;
                    int n2=get_ubyte(offs++);
                    int ptr =(n&63)*0x100+n2;
                    offs=ptr;
                    n=get_ubyte(offs++);
                }

                // if the string is too long restart and mess it up
                if (n+20+p>size/2)
                    p=0;

                while(n-->0)
                {
                    out[p++] = visible_char_map[get_ubyte(offs++)];
                }
                out[p++]='.';
                n=get_ubyte(offs++);
            }
            if (savedoffs)
                offs=savedoffs;
            out[p++]=0;
            return offs;
        }
        void parse()
        {
            m_header.parse(*this);
            int offs=12;
            int q=0;
            int cnt=m_header.qdcount;
            while (cnt-->0)
            {
                offs = m_questions[q].parse(*this,offs);
                if (offs>m_length)
                {
                    m_questions[q].qname[0]=0;
                    m_error=offs;
                    return;
                }
                q=1;    // not ++ ignore further Q's
            }
            q=0;
            cnt=m_header.ancount;
            while (cnt-->0)
            {
                offs = m_answer[q].parse(*this,offs);
                q=1;    // not ++ ignore further Q's
                if (offs>m_length)
                {
                    m_error=offs;
                    return;
                }
            }
            q=0;
            cnt=m_header.nscount;
            while (cnt-->0)
            {
                offs = m_authority[q].parse(*this,offs);
                q=1;    // not ++ ignore further Q's
                if (offs>m_length)
                {
                    m_error=offs;
                    return;
                }
            }
            q=0;
            cnt=m_header.arcount;
            while (cnt-->0)
            {
                offs = m_additional[q].parse(*this,offs);
                q=1;    // not ++ ignore further Q's
                if (offs>m_length)
                {
                    m_error=offs;
                    return;
                }
            }
            if (offs>m_length)
                m_error=offs;

            if (m_opt_rr)
            {
                m_edns0=true;
                unsigned long ttl = m_opt_rr->ttl;
                m_do=(ttl>>15)&1;
                m_extended_rcode=ttl>>24;
                m_edns_version=(ttl>>16)&0xff;
                m_z=ttl&0x7fff;
                m_udp_size=m_opt_rr->rr_class;

            }
        }

        unsigned int  get_ubyte (int offs)                     { if(offs>=m_length)return 0;  return int(m_data[offs]); }
        // returns 16 bit number at byte offset offs
        unsigned int  get_ushort(int offs)                     { if(offs>=m_length)return 0;  return (int(m_data[offs])<<8)|int(m_data[offs+1]); }
        bool           get_bit   (int offs,int bit)             { if(offs>=m_length)return 0;  return ((get_ushort(offs)<<bit)&0x8000)==0x8000; }
        unsigned int  get_bits  (int offs,int bit,int bits) { if(offs>=m_length)return 0;  return ((get_ushort(offs)<<bit)&0xffff)>>(16-bits); }



};

class Parse_dns : public Packet_handler
{
    public:
    Parse_dns()
    {
        init();
    }

    const char *table_name() const;
    virtual void add_columns(Table &table);
    bool fill_in_row(DNSMessage &message, Row &destination_Row);
    virtual bool parse(Packet &packet);
    private:
    void init();
    Str_conv converter;

    IP_header_to_table m_ip_helper;

    Int_accessor *acc_s              ;
    Int_accessor *acc_us             ;
    Int_accessor *acc_ether_type     ;
    Int_accessor *acc_protocol       ;
    Int_accessor *acc_src_port       ;
    Int_accessor *acc_msg_id         ;
    Int_accessor *acc_msg_size       ;
    Int_accessor *acc_opcode         ;
    Int_accessor *acc_rcode          ;
    Int_accessor *acc_extended_rcode ;
    Int_accessor *acc_edns_version   ;
    Int_accessor *acc_z              ;
    Int_accessor *acc_udp_size       ;
    Int_accessor *acc_qd_count       ;
    Int_accessor *acc_an_count       ;
    Int_accessor *acc_ns_count       ;
    Int_accessor *acc_ar_count       ;
    Int_accessor *acc_qtype          ;
    Int_accessor *acc_qclass         ;
    Int_accessor *acc_atype          ;
    Int_accessor *acc_aclass         ;
    Int_accessor *acc_attl           ;
    Bool_accessor *acc_qr            ;
    Bool_accessor *acc_aa            ;
    Bool_accessor *acc_tc            ;
    Bool_accessor *acc_rd            ;
    Bool_accessor *acc_cd            ;
    Bool_accessor *acc_ra            ;
    Bool_accessor *acc_ad            ;
    Bool_accessor *acc_do            ;
    Bool_accessor *acc_edns0         ;
    String_accessor *acc_qname       ;
    String_accessor *acc_aname       ;
    String_accessor *acc_src_addr    ;
    String_accessor *acc_dst_addr    ;
    Table *m_table;
};

};

#endif

