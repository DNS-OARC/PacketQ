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



}
