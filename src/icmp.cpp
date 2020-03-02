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

#include "icmp.h"
#include "output.h"
#include "packet_handler.h"
#include "packetq.h"
#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace packetq {

Parse_icmp::Parse_icmp()
{
    table_name = "icmp";

    add_packet_columns();
    add_lookup_tables();
}

void Parse_icmp::add_packet_columns()
{
    m_ip_helper.add_packet_columns(*this);

    add_packet_column("type", "", Coltype::_int, COLUMN_TYPE);
    add_packet_column("code", "", Coltype::_int, COLUMN_CODE);
    add_packet_column("echo_identifier", "", Coltype::_int, COLUMN_ECHO_IDENTIFIER);
    add_packet_column("echo_sequence", "", Coltype::_int, COLUMN_ECHO_SEQUENCE);
    add_packet_column("du_protocol", "", Coltype::_int, COLUMN_DU_PROTOCOL);
    add_packet_column("du_src_addr", "", Coltype::_text, COLUMN_DU_SRC_ADDR);
    add_packet_column("du_dst_addr", "", Coltype::_text, COLUMN_DU_DST_ADDR);
    add_packet_column("desc", "", Coltype::_text, COLUMN_DESC);
}

void Parse_icmp::add_lookup_tables()
{
}

Packet::ParseResult Parse_icmp::parse(Packet& packet, const std::vector<int>& columns, Row& destination_row, bool sample)
{
    if (packet.m_ip_header.proto != IPPROTO_ICMP)
        return Packet::ERROR;
    if (packet.m_ip_header.ethertype != 2048) // we dont support ICMPv6 yet
        return Packet::ERROR;

    if (!sample)
        return Packet::NOT_SAMPLED;

    if (packet.m_len < 2)
        return Packet::ERROR;

    Row* r = &destination_row;

    m_ip_helper.assign(r, &packet.m_ip_header, columns);

    unsigned char*  raw        = packet.m_data;
    int             type       = raw[0];
    int             code       = raw[1];
    int             identifier = 0, sequence = 0, protocol = 0;
    RefCountString *src_addr = 0, *dst_addr = 0;
    bool            src_addr_used = false, dst_addr_used = false;

    switch (type) {
    case 0:
        if (packet.m_len < 8)
            return Packet::ERROR;
        identifier = get_short(&raw[4]);
        sequence   = get_short(&raw[6]);
        break;
    case 3: {
        IP_header head;
        if (packet.m_len < 8 + 20)
            return Packet::ERROR;
        head.decode(&raw[8], packet.m_ip_header.ethertype, 0);
        protocol = head.proto;
        src_addr = v4_addr2str(head.src_ip);
        dst_addr = v4_addr2str(head.dst_ip);
    } break;
    case 8:
        if (packet.m_len < 8)
            return Packet::ERROR;
        identifier = get_short(&raw[4]);
        sequence   = get_short(&raw[6]);
        break;
    }

    for (auto i = columns.begin(), end = columns.end(); i != end; ++i) {
        switch (*i) {
        case COLUMN_TYPE:
            acc_type.value(r) = type;
            break;

        case COLUMN_CODE:
            acc_code.value(r) = code;
            break;

        case COLUMN_ECHO_IDENTIFIER:
            acc_echo_identifier.value(r) = identifier;
            break;

        case COLUMN_ECHO_SEQUENCE:
            acc_echo_sequence.value(r) = sequence;
            break;

        case COLUMN_DU_PROTOCOL:
            acc_du_protocol.value(r) = protocol;
            break;

        case COLUMN_DU_SRC_ADDR:
            acc_du_src_addr.value(r) = src_addr ? src_addr : RefCountString::construct("");
            src_addr_used            = true;
            break;

        case COLUMN_DU_DST_ADDR:
            acc_du_dst_addr.value(r) = dst_addr ? dst_addr : RefCountString::construct("");
            dst_addr_used            = true;
            break;

        case COLUMN_DESC:
            switch (type) {
            case 0:
                acc_desc.value(r) = RefCountString::construct("Echo Reply");
                break;
            case 3:
                switch (code) {
                case 0:
                    acc_desc.value(r) = RefCountString::construct("Destination network unreachable");
                    break;
                case 1:
                    acc_desc.value(r) = RefCountString::construct("Destination host unreachable");
                    break;
                case 2:
                    acc_desc.value(r) = RefCountString::construct("Destination protocol unreachable");
                    break;
                case 3:
                    acc_desc.value(r) = RefCountString::construct("Destination port unreachable");
                    break;
                default:
                    acc_desc.value(r) = RefCountString::construct("Destination unreachable");
                    break;
                }
                break;
            case 4:
                acc_desc.value(r) = RefCountString::construct("Source quench");
                break;
            case 5:
                acc_desc.value(r) = RefCountString::construct("Redirect Message");
                break;
            case 6:
                acc_desc.value(r) = RefCountString::construct("Alternate Host Address");
                break;
            case 8:
                acc_desc.value(r) = RefCountString::construct("Echo Request");
                break;
            case 9:
                acc_desc.value(r) = RefCountString::construct("Router Advertisement");
                break;
            case 10:
                acc_desc.value(r) = RefCountString::construct("Router Solicitation");
                break;
            case 11:
                acc_desc.value(r) = RefCountString::construct("Time Exceeded");
                break;
            case 12:
                acc_desc.value(r) = RefCountString::construct("Bad IP header");
                break;
            case 13:
                acc_desc.value(r) = RefCountString::construct("Timestamp");
                break;
            case 14:
                acc_desc.value(r) = RefCountString::construct("Timestamp Reply");
                break;
            case 15:
                acc_desc.value(r) = RefCountString::construct("Information Request");
                break;
            case 16:
                acc_desc.value(r) = RefCountString::construct("Information Reply");
                break;
            case 17:
                acc_desc.value(r) = RefCountString::construct("Address Mask Request");
                break;
            case 18:
                acc_desc.value(r) = RefCountString::construct("Address Mask Reply");
                break;
            case 30:
                acc_desc.value(r) = RefCountString::construct("Traceroute");
                break;
            default:
                acc_desc.value(r) = RefCountString::construct("UNKNOWN TYPE");
            }
            break;
        }
    }

    if (src_addr && !src_addr_used)
        src_addr->dec_refcount();
    if (dst_addr && !dst_addr_used)
        dst_addr->dec_refcount();

    return Packet::OK;
}

void Parse_icmp::on_table_created(Table* table, const std::vector<int>& columns)
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

} // namespace packetq
