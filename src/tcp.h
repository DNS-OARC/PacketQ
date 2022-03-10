/*
 * Copyright (c) 2017-2022, OARC, Inc.
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

#ifndef __packetq_tcp_h
#define __packetq_tcp_h

#include <stdio.h>
#include <stdint.h>

namespace packetq {

struct _in6_addr {
    union {
        uint8_t  __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __in6_u; /* 128-bit IP6 address */
};

typedef struct _in6_addr in6addr_t;

class Payload;

/** Assembles tcp packets into streams and returns data
    when 'fin' has been recieved
 */
unsigned char* assemble_tcp(
    Payload&       payload,
    in6addr_t*     src_ip,
    in6addr_t*     dst_ip,
    unsigned short src_port,
    unsigned short dst_port,
    unsigned int*  rest,
    unsigned int   seq,
    unsigned char* data,
    int            len,
    char           syn,
    char           fin,
    char           rst,
    char           ack);

} // namespace packetq

#endif // __packetq_tcp_h
