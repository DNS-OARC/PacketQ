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

#include "pcap.h"

#include <stdio.h>
#include <stdlib.h>

namespace packetq {

bool Pcap_file::get_header()
{
    // establish: byte order and file format
    int res = get_int32();
    if (res != 0xa1b2c3d4) {
        res = flip32(res);
        if (res != 0xa1b2c3d4) {
            if (!m_gzipped) {
                set_gzipped();
                return get_header();
            }
            return false;
        }
        m_reverse_order = true;
    }
    // establish version
    int major_version = get_int16();
    int minor_version = get_int16();
    if (major_version != 2 || minor_version != 4) {
        printf("maj:%d min:%d\n", major_version, minor_version);
        return false;
    }
    // check for 0 timezone offset and accuracy
    if (!get_int32() == 0) {
        printf("timezone offset != 0");
        return false;
    }
    if (!get_int32() == 0) {
        printf("timezone offset != 0");
        return false;
    }

    m_snapshot_length = get_int32();
    // check for ethernet packets
    m_link_layer_type = get_int32();
    if (m_link_layer_type != 1 && m_link_layer_type != 101) {
        fprintf(stderr, "PCAP file unsupported linklayer (%d)\n", m_link_layer_type);
        return false;
    }
    return true;
}

unsigned char* Pcap_file::get_packet(int& len, int& s, int& us)
{
    s   = 0;
    us  = 0;
    len = 0;
    s   = get_int32();
    us  = get_int32();
    len = get_int32();

    // skip past reallen
    get_int32();

    if (get_eof() || len < 0)
        return 0;

    unsigned char* buf = get_bytes(len);

    return buf;
}

} // namespace packetq
