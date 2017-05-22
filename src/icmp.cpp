/*
 * Copyright (c) 2017, OARC, Inc.
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

#include "packetq.h"
#include "tcp.h"
#include "packet_handler.h"
#include <stdio.h>
#include "output.h"
#include "icmp.h"
#include <stdlib.h>
#include <string.h>

namespace packetq {

Parse_icmp::Parse_icmp()
{
    table_name = "icmp";

    add_packet_columns();
}

void Parse_icmp::add_packet_columns()
{
    m_ip_helper.add_packet_columns(*this);

    add_packet_column("type",            "", Coltype::_int, COLUMN_TYPE);
    add_packet_column("code",            "", Coltype::_int, COLUMN_CODE);
    add_packet_column("echo_identifier", "", Coltype::_int, COLUMN_ECHO_IDENTIFIER);
    add_packet_column("echo_sequence",   "", Coltype::_int, COLUMN_ECHO_SEQUENCE);
    add_packet_column("du_protocol",     "", Coltype::_int, COLUMN_DU_PROTOCOL);
    add_packet_column("du_src_addr",     "", Coltype::_text, COLUMN_DU_SRC_ADDR);
    add_packet_column("du_dst_addr",     "", Coltype::_text, COLUMN_DU_DST_ADDR);
    add_packet_column("desc",            "", Coltype::_text, COLUMN_DESC);
}

Packet::ParseResult Parse_icmp::parse(Packet &packet, const std::vector<int> &columns, Row &destination_row, bool sample)
{
    if (packet.m_ip_header.proto != IPPROTO_ICMP)
        return Packet::ERROR;
    if (packet.m_ip_header.ethertype != 2048) // we dont support ICMPv6 yet
        return Packet::ERROR;

    if (!sample)
        return Packet::NOT_SAMPLED;

    Row *r = &destination_row;

    m_ip_helper.assign(r, &packet.m_ip_header, columns);

    unsigned char *raw = packet.m_data;
    int type=raw[0];
    int code=raw[1];
    acc_type.value(r) = type;
    acc_code.value(r) = code;
    char desc[300];
    memset(desc, 0, sizeof(desc));

    switch(type)
    {
        case(0):
            snprintf(desc, sizeof(desc) - 1, "Echo Reply");
            acc_echo_identifier.value(r) = get_short(&raw[4]);
            acc_echo_sequence.value(r) = get_short(&raw[6]);
            //    acc_echo_sequence->set_i(   r,4);
            break;
        case(3):
            {
                const char *what="";
                const char *codes[]={"network ","host ","protocol ","port "};
                if (code<4)
                    what=codes[code];
                snprintf(desc, sizeof(desc) - 1, "Destination %sunreachable",what);
                IP_header head;
                head.decode(&raw[8],packet.m_ip_header.ethertype,0);
                acc_du_protocol.value(r) = head.proto;
                acc_du_src_addr.value(r) = v4_addr2str(head.src_ip);
                acc_du_dst_addr.value(r) = v4_addr2str(head.dst_ip);
            }
            break;
        case(4):
            snprintf(desc, sizeof(desc) - 1, "Source quench");
            break;
        case(5):
            snprintf(desc, sizeof(desc) - 1, "Redirect Message");
            break;
        case(6):
            snprintf(desc, sizeof(desc) - 1, "Alternate Host Address");
            break;
        case(8):
            snprintf(desc, sizeof(desc) - 1, "Echo Request");
            acc_echo_identifier.value(r) = get_short(&raw[4]);
            acc_echo_sequence.value(r) = get_short(&raw[6]);
            break;
        case(9):
            snprintf(desc, sizeof(desc) - 1, "Router Advertisement");
            break;
        case(10):
            snprintf(desc, sizeof(desc) - 1, "Router Solicitation");
            break;
        case(11):
            snprintf(desc, sizeof(desc) - 1, "Time Exceeded");
            break;
        case(12):
            snprintf(desc, sizeof(desc) - 1, "Bad IP header");
            break;
        case(13):
            snprintf(desc, sizeof(desc) - 1, "Timestamp");
            break;
        case(14):
            snprintf(desc, sizeof(desc) - 1, "Timestamp Reply");
            break;
        case(15):
            snprintf(desc, sizeof(desc) - 1, "Information Request");
            break;
        case(16):
            snprintf(desc, sizeof(desc) - 1, "Information Reply");
            break;
        case(17):
            snprintf(desc, sizeof(desc) - 1, "Address Mask Request");
            break;
        case(18):
            snprintf(desc, sizeof(desc) - 1, "Address Mask Reply");
            break;
        case(30):
            snprintf(desc, sizeof(desc) - 1, "Traceroute");
            break;
    }

    acc_desc.value(r) = RefCountString::construct(desc);

    return Packet::OK;
}

void Parse_icmp::on_table_created(Table *table, const std::vector<int> &columns)
{
    m_ip_helper.on_table_created(table, columns);

    acc_type            = table->get_accessor<int_column>("type");
    acc_code            = table->get_accessor<int_column>("code");
    acc_echo_identifier = table->get_accessor<int_column>("echo_identifier");
    acc_echo_sequence   = table->get_accessor<int_column>("echo_sequence");
    acc_du_protocol     = table->get_accessor<int_column>("du_protocol");
    acc_du_src_addr     = table->get_accessor<text_column>("du_src_addr");
    acc_du_dst_addr     = table->get_accessor<text_column>("du_dst_addr");
    acc_desc            = table->get_accessor<text_column>("desc");
}

}
