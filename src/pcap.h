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

#ifndef SEPCAP_H
#define SEPCAP_H
#include <stdio.h>
#include <stdlib.h>
#include "sql.h"
#include <zlib.h>
#include "segzip.h"

namespace se {

class Pcap_file
{
    public:
        static const bool TAKE_OVER_FP = true;

        Pcap_file(FILE *fp, bool take_over_fp=false)
        {
            m_fp_owned = take_over_fp;
            m_fp = fp;
            m_reverse_order     = false;
            m_packetbuffer      = 0;
            m_packetbuffer_len  = 0;
            m_eof               = false;
            m_snapshot_length   = 0;
            m_link_layer_type   = 0;
            m_gzipped           = false;
        }
        ~Pcap_file()
        {
            if (m_packetbuffer)
                delete []m_packetbuffer;
            if (m_fp_owned)
                fclose(m_fp);
        }

        bool            get_header();

        unsigned char   *get_packet(  int &len, int &s, int &us );

        int     get_int32()
        {
            int res;
            get_bytes((unsigned char *)&res,4);
            if (m_reverse_order)
            {
               return flip32(res);
            }
            return res;
        }
        int     get_int16()
        {
            short res;
            get_bytes((unsigned char *)&res,2);
            if (m_reverse_order)
            {
               return flip16(res);
            }
            return res;
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
        int     get_bytes(unsigned char *dst,int count)
        {
            Buffer &buf = m_gzipped ? m_zipbuffer:m_filebuffer;
            if (count == 0)
                return 0;

            int bytes=0;
            while(count>0)
            {
                if (buf.m_buffer_len == buf.m_buffer_pos)
                {
                    buffread();
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
                    m_zip.inflate(m_filebuffer,m_zipbuffer);
            }
        }
        void set_gzipped()
        {
            m_gzipped=true;
            m_filebuffer.m_buffer_pos = 0;
        }
        int flip16(unsigned short i)
        {
            unsigned int r=i&0xff;
            r<<=8;
            i>>=8;
            r|=i&0xff;
            return int(r);
        }
        int flip32(unsigned int i)
        {
            unsigned int r=i&0xff;
            r<<=8;
            i>>=8;
            r|=i&0xff;
            r<<=8;
            i>>=8;
            r|=i&0xff;
            r<<=8;
            i>>=8;
            r|=i&0xff;
            return int(r);
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
        int  get_link_layer_type() {return m_link_layer_type;}

    private:
        int     m_snapshot_length;
        int     m_link_layer_type;
        bool    m_reverse_order;
        bool    m_eof;
        bool    m_gzipped;
        FILE    *m_fp;
        bool    m_fp_owned;

        unsigned char   *m_packetbuffer;
        int              m_packetbuffer_len;

        Buffer           m_filebuffer;
        Buffer           m_zipbuffer;
        Zip              m_zip;
};

};

#endif
