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
#ifndef SEJSON_H
#define SEJSON_H
#include <stdio.h>
#include <stdlib.h>
#include "sql.h"
#include "segzip.h" 

namespace se {

class Json_file 
{
    public:
        Json_file(FILE *fp)
        {
            m_gzipped           = true;
            m_fp                = fp;
            m_packetbuffer      = 0;
            m_packetbuffer_len  = 0;
            m_eof               = false;
            m_cur_c             = -1;
            if (peek()<0)
            {
                m_gzipped = false;
                if (m_fp)
                    fseek(m_fp,0,SEEK_SET);
                if (m_packetbuffer)
                    delete []m_packetbuffer;
                m_packetbuffer      = 0;
                m_packetbuffer_len  = 0;
                m_eof               = false;
                m_cur_c             = -1;
            }
        }
        ~Json_file()
        {
            if (m_packetbuffer)
                delete []m_packetbuffer;
        }
        bool read_file();

        int peek()
        {
            if (m_cur_c==-1)
            {
                unsigned char *c = get_bytes(1); 
                if (c)
                {
                    m_cur_c = *c;
//                    printf("%c",*c);
                }
            }
            return m_cur_c;
        }

        int eat()
        {
            int c = peek();
            m_cur_c=-1;
            return c;
        }

        unsigned char *get_bytes(int count)
        {
            Buffer &buf = m_gzipped ? m_zipbuffer:m_filebuffer;
            if (count<buf.m_buffer_len-buf.m_buffer_pos)
            {
                unsigned char *ptr=&buf.m_buffer[ buf.m_buffer_pos ];
                buf.m_buffer_pos+=count;
                return ptr;
            }

            unsigned char * bufp = get_pbuffer(count+400);
            int r = get_bytes(bufp,count);        
            if (r==count)
                return bufp;
            return 0;
        }
        int get_bytes(unsigned char *dst,int count)
        {
            bool zip = m_gzipped;
            Buffer &buf = m_gzipped ? m_zipbuffer:m_filebuffer;
            if (count == 0)
                return 0;

            int bytes=0;
            while(count>0)
            {
                if (buf.m_buffer_len == buf.m_buffer_pos)
                {
                    buffread();
                    if (zip != m_gzipped)
                        return get_bytes(dst, count);
                    if (buf.m_buffer_len==0)
                    {
                        m_eof=true;
                        return bytes;
                    }
                }
                int n=(buf.m_buffer_len-buf.m_buffer_pos)>count?count:buf.m_buffer_len-buf.m_buffer_pos;
                for (int i=0;i<n;i++)
                {
                    *dst++ = buf.m_buffer[buf.m_buffer_pos++];
                }
                bytes+=n;
                count -= n;
            }
            return bytes;
        }
        void buffread()
        {
            if (!m_fp)
                throw Error("No file");

            Buffer &buf =  m_filebuffer;
            if (buf.m_buffer_len == buf.m_buffer_pos)
            {
                buf.m_buffer_len = (int)fread(buf.m_buffer,1,buf.m_nextread,m_fp);
                buf.m_buffer_pos = 0;
                buf.m_nextread = sizeof(buf.m_buffer);
            }
            if (m_gzipped)
            {
                if (m_zip.m_error || buf.m_buffer_len == buf.m_buffer_pos)
                {
                    m_zipbuffer.m_buffer_pos = m_zipbuffer.m_buffer_len = 0;
                    return;
                }
                if (m_zipbuffer.m_buffer_len == m_zipbuffer.m_buffer_pos)
                {
                    if(!m_zip.inflate(m_filebuffer,m_zipbuffer))
                    {
                        buf.m_buffer_len = 0;
                        buf.m_buffer_pos = 0;
                        m_zipbuffer.m_buffer_pos = m_zipbuffer.m_buffer_len = 0;
                    }
                }
            }
        }
        void set_gzipped()
        {
            m_gzipped=true;
            m_filebuffer.m_buffer_pos = 0;
        }

        unsigned char *get_pbuffer(int len)
        {
            if (!m_packetbuffer || len >= m_packetbuffer_len)
            {
                if (m_packetbuffer)
                {
                    delete []m_packetbuffer;
                    m_packetbuffer = 0;
                }
                m_packetbuffer_len = len +4096;
                m_packetbuffer = new unsigned char [m_packetbuffer_len];
                if (!m_packetbuffer)
                    m_packetbuffer_len = 0;
            }
            return m_packetbuffer;
        }
        bool get_eof() {return m_eof;}

    private:
        bool    m_eof;
        bool    m_gzipped;
        FILE    *m_fp;
        int     m_cur_c;

        unsigned char   *m_packetbuffer;
        int              m_packetbuffer_len;

        Buffer           m_filebuffer;
        Buffer           m_zipbuffer;
        Zip              m_zip;
};

};

#endif  
