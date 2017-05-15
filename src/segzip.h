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
            m_init    = true;
            m_error   = false;
            m_run_end = false;
            m_stream.next_out = 0;
            m_stream.avail_out = 0;
        }
        ~Zip()
        {
            if (m_run_end)
                ::inflateEnd(&m_stream);
        }
        bool inflate(Buffer &in,Buffer &out)
        {
            if (m_error)
            {
                in.m_buffer_pos  = in.m_buffer_len;
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
                    out.m_buffer_len = 0;
                    in.m_buffer_pos = in.m_buffer_len;
                    return false;
                }
            }
            m_stream.next_in = &in.m_buffer[in.m_buffer_pos];
            m_stream.avail_in = in.m_buffer_len-in.m_buffer_pos;

            int ret = ::inflate(&m_stream,Z_NO_FLUSH);

            if (ret != Z_OK)
                ::inflateEnd(&m_stream);
            else
                m_run_end=true;
            if (ret != Z_OK && ret != Z_STREAM_END)
            {
                m_error = true;
                out.m_buffer_len = 0;
                in.m_buffer_pos = in.m_buffer_len=0;
                return false;
            }

            in.m_buffer_pos = in.m_buffer_len-m_stream.avail_in;
            out.m_buffer_len = sizeof(out.m_buffer) - m_stream.avail_out;
            out.m_buffer_pos = 0;
            return true;
        }
        bool m_init;
        bool m_run_end;
        bool m_error;
        z_stream m_stream;
};

};

#endif
