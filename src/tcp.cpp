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

#include "tcp.h"
#include "packet_handler.h"

#include <cstring>
#include <list>
#include <map>
#include <stdlib.h>

namespace packetq {

/// TCP Stream id class - serves as the key in the streams map
class Stream_id {
public:
    /// constructor
    Stream_id()
        : m_src_port(0)
        , m_dst_port(0)
    {
        memset(&m_src_ip, 0, sizeof(m_src_ip));
        memset(&m_dst_ip, 0, sizeof(m_dst_ip));
    }
    /// constructor taking source and destination adresses
    Stream_id(in6addr_t& src_ip,
        in6addr_t&       dst_ip,
        unsigned short   src_port,
        unsigned short   dst_port)
    {
        m_src_ip   = src_ip;
        m_dst_ip   = dst_ip;
        m_src_port = src_port;
        m_dst_port = dst_port;
    }

    /// < comparison operator for the std::map
    bool operator<(const Stream_id& rhs) const
    {
        return memcmp(this, &rhs, sizeof(Stream_id)) < 0;
    }

private:
    in6addr_t      m_src_ip, m_dst_ip;
    unsigned short m_src_port, m_dst_port;
};

/// TCP data segment container
/** Data_segment contains the data found in a single tcp packet
 * Data_segment are inerted into a list in the Stream class
 */
class Data_segment {
public:
    /// Constructor taking a memory block with packet content
    Data_segment(unsigned char* data, unsigned int len)
    {
        m_datasize = len;
        m_data     = new unsigned char[len];
        for (unsigned int i = 0; i < len; i++) {
            m_data[i] = data[i];
        }
    }
    /// Copy constructor
    Data_segment(const Data_segment& other)
    {
        m_datasize = other.m_datasize;
        m_data     = new unsigned char[m_datasize];
        for (unsigned int i = 0; i < m_datasize; i++) {
            m_data[i] = other.m_data[i];
        }
    }
    /// Destructor
    ~Data_segment()
    {
        delete[] m_data;
    }

    /// size of the data
    unsigned int m_datasize;
    /// pointer to the data
    unsigned char* m_data;
};

int g_count = 0;

/// TCP Stream class
/** The Stream class has an Stream_id and a list of Data_segemnts that make up
 *  a tcp data stream.
 *  The Streams are organized into a global map ( g_tcp_streams ) indexed by a Stream_id
 */
class Stream {
public:
    /// Constructor
    Stream()
    {
        m_ser     = g_count++;
        m_content = false;
        m_nseq    = false;
        m_seq     = 0;
    }
    /// add a datasegment to the stream
    /** If the segment has the expected sequence number
         *  the segment will be added to the list
         */
    void add(bool syn, unsigned int seq, Data_segment& s)
    {
        m_content = true;
        if (!m_segments.size() || syn)
            m_seq = seq;

        if (m_seq == seq) {
            m_content = true;
            if ((s.m_datasize > 0 && s.m_datasize <= 65535)) {
                m_segments.push_back(s);
                m_seq = seq + s.m_datasize;
            }
        }
    }
    /// checka if there's any content in the stream
    bool has_content()
    {
        return m_content;
    }
    /// Erase (and free) all segments and reset state
    void erase()
    {
        m_content = false;
        m_nseq    = false;
        m_segments.clear();
    }
    /// return the streams data size
    int get_size()
    {
        int size = 0;
        for (std::list<Data_segment>::iterator it = m_segments.begin();
             it != m_segments.end(); it++) {
            size += it->m_datasize;
        }
        return size;
    }
    /// debug functionality to dump a streams content
    void dump()
    {
        int start = 2;
        for (std::list<Data_segment>::iterator it = m_segments.begin();
             it != m_segments.end(); it++) {
            for (unsigned int i = start; i < it->m_datasize; i++) {
                printf("%02x", it->m_data[i]);
            }
            start = 0;
        }
        printf("\n");
    }
    /// returns the data in the stream
    /** The returned data is located in a static buffer shared by all streams
         *  the data is valid until the next call to get_buffer()
         */
    unsigned char* get_buffer()
    {
        int p = 0;
        for (std::list<Data_segment>::iterator it = m_segments.begin();
             it != m_segments.end(); it++) {
            for (unsigned int i = 0; i < it->m_datasize; i++) {
                m_buffer[p++] = it->m_data[i];
                if (p >= 0xffff)
                    return m_buffer;
            }
        }
        return m_buffer;
    }

private:
    unsigned int            m_seq;
    int                     m_ser;
    bool                    m_content;
    bool                    m_nseq;
    std::list<Data_segment> m_segments;

    static unsigned char m_buffer[0x10000];
};
unsigned char Stream::m_buffer[0x10000];

std::map<Stream_id, Stream> g_tcp_streams;

/// assemble_tcp builds datastreams out of tcp packets
/** TCP packets are inserted into streams. When the streams are closed
 *  the contained data is returned as a pointer the data
 *  it is up to the caller to free() the memory returned.
 */
unsigned char*
assemble_tcp(
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
    char           ack)
{
    Stream_id id(*src_ip, *dst_ip, src_port, dst_port);
    Stream&   str        = g_tcp_streams[id];
    bool      data_avail = false;

    if (!str.has_content()) {
        Data_segment seg(data, len);
        str.add(syn, seq, seg);
    } else {
        if (rst == 1) {
            str.erase();
        } else if (syn == 1) {
            str.erase();
            Data_segment seg(data, len);
            str.add(syn, seq, seg);
        } else {
            Data_segment seg(data, len);
            str.add(syn, seq, seg);
        }
    }

    data = 0;
    if (str.has_content()) {
        int            size     = str.get_size();
        unsigned char* buffer   = str.get_buffer();
        int            dns_size = (int(buffer[0]) << 8) | buffer[1];

        data_avail = (fin == 1) && (rst == 0);
        if (data_avail || dns_size + 2 == size) {
            *rest = size;
            if (*rest > 0xffff)
                *rest = 0xffff;
            data      = (unsigned char*)payload.alloc(*rest);
            memcpy(data, buffer, *rest);
            str.erase();
            g_tcp_streams.erase(id);
        }
    }
    return data;
}

} // namespace packetq
