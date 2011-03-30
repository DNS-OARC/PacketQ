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
#ifndef SEGZIP_H
#define SEGZIP_H
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h> 

namespace se {

class Buffer
{
    public:
    Buffer()
    {
        m_buffer_len    = 0;
        m_buffer_pos    = 0;
        m_nextread      = 1024;
    }
    int size() {return sizeof(m_buffer);}
    unsigned char    m_buffer[0x40000];
    int              m_nextread;
    int              m_buffer_len;
    int              m_buffer_pos;
};

class Zip
{
    public:
        Zip()
        {
            m_init = true;
            m_error = false;
            m_stream.next_out = 0;
            m_stream.avail_out = 0;
        }
        bool inflate(Buffer &in,Buffer &out)
        {
            if (m_error)
            {
                in.m_buffer_pos = in.m_buffer_len;
                out.m_buffer_len = 0;
                return false;
            }
            out.m_buffer_pos = 0;
            out.m_buffer_len = sizeof(out.m_buffer);
            m_stream.next_out = &out.m_buffer[out.m_buffer_pos];
            m_stream.avail_out = out.m_buffer_len - out.m_buffer_pos;
            if (m_init)
            {
                m_stream.next_in = 0;
                m_stream.avail_in = 0;
                m_stream.zalloc=0;
                m_stream.zfree=0;
                m_stream.opaque=0;
                m_init=false;
                if (inflateInit2(&m_stream,15+32)!=Z_OK)
                {
                    m_error=true;
                    in.m_buffer_pos = in.m_buffer_len;
                    return false;
                }
            }
            m_stream.next_in = &in.m_buffer[in.m_buffer_pos];
            m_stream.avail_in = in.m_buffer_len-in.m_buffer_pos;

            int ret = ::inflate(&m_stream,Z_NO_FLUSH); 
            
            if (ret != Z_OK)
                ::inflateEnd(&m_stream);
            if (ret != Z_OK && ret != Z_STREAM_END)
            {
                m_error = true;
                in.m_buffer_pos = in.m_buffer_len=0;
                return false;
            }

            in.m_buffer_pos = in.m_buffer_len-m_stream.avail_in;
            out.m_buffer_len = sizeof(out.m_buffer) - m_stream.avail_out;
            out.m_buffer_pos = 0;
            return true;
        }
        bool m_init;
        bool m_error;
        z_stream m_stream;
};

};

#endif  
