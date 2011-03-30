/*! \file */ 
/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 *                  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ##################################################################### 
 *
 */

#ifndef D2TCP_H
#define D2TCP_H

#include <stdio.h>

// Hack for Linux which does not include this in ethernet.h/ethertypes.h
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

namespace se {

struct in6_addr {
        union {
                unsigned char  __u6_addr8[16];
                unsigned short  __u6_addr16[8];
                unsigned int  __u6_addr32[4];
        } __in6_u;                    /* 128-bit IP6 address */
};

typedef struct in6_addr in6addr_t;




class Payload;

/** Assembles tcp packets into streams and returns data 
    when 'fin' has been recieved
 */
unsigned char *assemble_tcp(
	Payload &payload,
	in6addr_t *src_ip, 
	in6addr_t *dst_ip, 
	unsigned short src_port,
	unsigned short dst_port,
	unsigned int *rest,
	unsigned int seq,
	unsigned char *data, 
	int len,
	char syn,
	char fin,
	char rst,
	char ack);
}
#endif

