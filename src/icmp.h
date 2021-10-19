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

#ifndef __packetq_icmp_h
#define __packetq_icmp_h

#include <assert.h>
#include <cctype>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "output.h"
#include "packet_handler.h"
#include "sql.h"
#include "tcp.h"

namespace packetq {

class Parse_icmp : public Packet_handler {
public:
    enum {
        COLUMN_TYPE = IP_header_to_table::COLUMN_FRAGMENTS + 1,
        COLUMN_CODE,
        COLUMN_ECHO_IDENTIFIER,
        COLUMN_ECHO_SEQUENCE,
        COLUMN_DU_PROTOCOL,
        COLUMN_DU_SRC_ADDR,
        COLUMN_DU_DST_ADDR,
        COLUMN_DESC
    };

    Parse_icmp();

    virtual void                on_table_created(Table* table, const std::vector<int>& columns);
    virtual Packet::ParseResult parse(Packet& packet, const std::vector<int>& columns, Row& destination_row, bool sample);

    void add_packet_columns();
    void add_lookup_tables();

private:
    Str_conv converter;

    IP_header_to_table m_ip_helper;

    Int_accessor  acc_type;
    Int_accessor  acc_code;
    Int_accessor  acc_echo_identifier;
    Int_accessor  acc_echo_sequence;
    Int_accessor  acc_du_protocol;
    Text_accessor acc_du_src_addr;
    Text_accessor acc_du_dst_addr;
    Text_accessor acc_desc;
};

} // namespace packetq

#endif // __packetq_icmp_h
