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
#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"

namespace se {

bool Pcap_file::get_header()
{
    // establish: byte order and file format 
    int res = get_int32();
    if (res!=0xa1b2c3d4)
    {
        m_reverse_order = true;
        res = get_int32();
        if (res!=0xa1b2c3d4)
        {
            if (!m_gzipped)
            {
                m_reverse_order = false;
                set_gzipped();
                return get_header();
            }
            return false;
        }
    }
    // establish version 
    int major_version = get_int16(); 
    int minor_version = get_int16(); 
    if (major_version!=2 || minor_version!=4)
    {
        printf("maj:%d min:%d\n",major_version,minor_version); 
        return false;
    }
    // check for 0 timezone offset and accuracy
    if (!get_int32()==0)
    {
        printf("timezone offset != 0");
        return false;
    }
    if (!get_int32()==0)
    {
        printf("timezone offset != 0");
        return false;
    }

    m_snapshot_length = get_int32();
    // check for ethernet packets
    int link_layer_type = get_int32();
    if (link_layer_type!=1)
    {
        printf("linklayer != 1");
        return false;
    }
    return true;
}

unsigned char *Pcap_file::get_packet(int &len, int &s, int &us)
{
    s=0;
    us=0;
    len=0;
    s   = get_int32();
    us  = get_int32();
    len = get_int32();
    int reallen = get_int32();
   

    if (get_eof() || len < 0)
        return 0;

    unsigned char * buf = get_bytes(len); 

    return buf;
}
}
