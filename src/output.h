/*
 * Copyright (c) 2017-2024 OARC, Inc.
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

#ifndef __packetq_output_h
#define __packetq_output_h

#include <stdio.h>
#include <stdlib.h>

namespace packetq {

class Output {
    char m_buffer[0x10000];
    char m_diglut[0x100][4];
    int  m_len;
    int  m_tot;

public:
    Output()
    {
        for (int i = 0; i < 256; i++)
            snprintf(m_diglut[i], 4, "%d", i);

        m_len = 0;
        m_tot = 0;
    }
    ~Output()
    {
        //		print();
    }
    void reset() { m_len = 0; }
    void print()
    {
        if (!m_len)
            return;
        fwrite(m_buffer, m_len, 1, stdout);
        m_tot += m_len;
        m_len = 0;
    }
    void flush()
    {
        print();
        fflush(stdout);
    }
    inline void add_q_string(const char* p)
    {
        m_buffer[m_len++] = '"';
        add_string_esc_json(p);
        m_buffer[m_len++] = '"';
    }
    inline void add_string_esc_json(const char* p)
    {
        static const char lut[] = "0123456789ABCDEF";
        if (m_len > sizeof(m_buffer) / 2)
            print();
        char c;
        while ((c = *p++)) {
            if (c == '\\') {
                m_buffer[m_len++] = '\\';
                c                 = '\\';
            } else if (c == '"') {
                m_buffer[m_len++] = '\\';
            } else if (c < 0x20) {
                m_buffer[m_len++] = '\\';
                m_buffer[m_len++] = 'u';
                m_buffer[m_len++] = '0';
                m_buffer[m_len++] = '0';
                m_buffer[m_len++] = lut[(c >> 4) & 0xf];
                m_buffer[m_len++] = lut[c & 0xf];
                continue;
            }
            m_buffer[m_len++] = c;
        }
    }
    inline void add_string_esc_xml(const char* p)
    {
        if (m_len > sizeof(m_buffer) / 2)
            print();
        char c;
        while ((c = *p++) > 'A') {
            m_buffer[m_len++] = c;
        }
        if (c == 0)
            return;
        p--;
        while ((c = *p++)) {
            if (c == '>') {
                m_buffer[m_len++] = '&';
                add_string("gt");
                c = ';';
            }
            if (c == '<') {
                m_buffer[m_len++] = '&';
                add_string("lt");
                c = ';';
            }
            if (c == '\'') {
                m_buffer[m_len++] = '&';
                add_string("apos");
                c = ';';
            }
            if (c == '"') {
                m_buffer[m_len++] = '&';
                add_string("quot");
                c = ';';
            }
            m_buffer[m_len++] = c;
            if (c == '&') {
                add_string("amp;");
            }
        }
    }
    inline void check()
    {
        if (m_len > sizeof(m_buffer) / 2)
            print();
    }
    inline void add_string(const char* p)
    {
        check();
        char c;
        while ((c = *p++)) {
            m_buffer[m_len++] = c;
        }
    }

    inline void add_hex_ushort(unsigned short v)
    {
        static const char lut[] = "0123456789abcdef";
        if (v & 0xf000) {
            m_buffer[m_len++] = lut[v >> 12];
            m_buffer[m_len++] = lut[(v >> 8) & 0xf];
            m_buffer[m_len++] = lut[(v >> 4) & 0xf];
            m_buffer[m_len++] = lut[v & 0xf];
            return;
        }
        if (v & 0xf00) {
            m_buffer[m_len++] = lut[(v >> 8) & 0xf];
            m_buffer[m_len++] = lut[(v >> 4) & 0xf];
            m_buffer[m_len++] = lut[v & 0xf];
            return;
        }
        if (v & 0xf0) {
            m_buffer[m_len++] = lut[(v >> 4) & 0xf];
            m_buffer[m_len++] = lut[v & 0xf];
            return;
        }
        m_buffer[m_len++] = lut[v & 0xf];
    }

    inline void add_attr_ipv6(const char* name, unsigned char* addr)
    {
        check();
        add_string_q(name);
        m_buffer[m_len++] = '=';
        m_buffer[m_len++] = '"';

        unsigned short digs[8];
        unsigned char* p           = addr;
        int            longest_run = 0;
        int            longest_p   = 9;
        int            cur_run     = 0;
        for (int i = 0; i < 8; i++) {
            digs[i] = ((unsigned short)(p[0]) << 8) | (unsigned short)(p[1]);
            if (digs[i] == 0) {
                cur_run++;
                if ((cur_run > 1) && (cur_run > longest_run)) {
                    longest_run = cur_run;
                    longest_p   = i + 1 - cur_run;
                }
            } else
                cur_run = 0;

            p += 2;
        }

        for (int i = 0; i < 8; i++) {
            if (i >= longest_p && i < longest_p + longest_run) {
                if (i == longest_p) {
                    if (i == 0)
                        m_buffer[m_len++] = ':';
                    m_buffer[m_len++] = ':';
                }
            } else {
                add_hex_ushort(digs[i]);
                if (i != 7)
                    m_buffer[m_len++] = ':';
            }
        }

        m_buffer[m_len++] = '"';
        m_buffer[m_len++] = ' ';
    }

    inline void add_attr_ipv4(const char* p, unsigned int i)
    {
        check();
        add_string_q(p);
        m_buffer[m_len++] = '=';
        m_buffer[m_len++] = '"';
        add_string_q(m_diglut[i & 255]);
        m_buffer[m_len++] = '.';
        add_string_q(m_diglut[(i >> 8) & 255]);
        m_buffer[m_len++] = '.';
        add_string_q(m_diglut[(i >> 16) & 255]);
        m_buffer[m_len++] = '.';
        add_string_q(m_diglut[(i >> 24)]);
        m_buffer[m_len++] = '"';
        m_buffer[m_len++] = ' ';
    }

    inline void add_attr_bool(const char* p, bool i)
    {
        if (!i)
            return;
        check();
        add_string_q(p);
        m_buffer[m_len++] = '=';
        m_buffer[m_len++] = '"';
        m_buffer[m_len++] = i ? '1' : '0';
        m_buffer[m_len++] = '"';
        m_buffer[m_len++] = ' ';
    }

    inline void add_int(unsigned int i)
    {
        check();
        if (i < 256) {
            add_string_q(m_diglut[i & 255]);
        } else {
            unsigned char d[64];

            unsigned char* cd = d;
            while (i > 0 && cd < (&d[0] + sizeof(d))) {
                unsigned int n = i;
                i              = i / 100;
                n              = n - (i * 100);
                *cd++          = n;
            }
            if (cd != d) {
                unsigned char t = *--cd;
                add_string_q(m_diglut[t]);
            }
            while (cd != d) {
                unsigned char t = *--cd;
                if (t >= 10)
                    add_string_q(m_diglut[t]);
                else {
                    m_buffer[m_len++] = '0';
                    m_buffer[m_len++] = '0' + t;
                }
            }
        }
    }
    inline void add_attr_int(const char* p, unsigned int i)
    {
        check();
        if (i == 0)
            return;
        add_string_q(p);
        m_buffer[m_len++] = '=';
        m_buffer[m_len++] = '"';
        add_int(i);
        m_buffer[m_len++] = '"';
        m_buffer[m_len++] = ' ';
    }

    inline void add_attr_str(const char* p, const char* t)
    {
        add_string(p);
        m_buffer[m_len++] = '=';
        m_buffer[m_len++] = '"';
        add_string_esc_json(t);
        m_buffer[m_len++] = '"';
        m_buffer[m_len++] = ' ';
    }

private:
    inline void add_string_q(const char* p)
    {
        char c;
        while ((c = *p++)) {
            m_buffer[m_len++] = c;
        }
    }
};

class Str_conv {
    char m_buffer[0x10000];
    char m_diglut[0x100][4];
    int  m_len;
    int  m_tot;

public:
    Str_conv()
    {
        for (int i = 0; i < 256; i++)
            snprintf(m_diglut[i], 4, "%d", i);

        m_len = 0;
        m_tot = 0;
    }
    ~Str_conv()
    {
        //		print();
    }
    const char* get()
    {
        m_buffer[m_len] = 0;
        return m_buffer;
    }
    int         get_len() { return m_len; }
    void        reset() { m_len = 0; }
    inline void add_attr_ipv6(unsigned char* addr)
    {
        unsigned short digs[8];
        unsigned char* p           = &addr[14];
        int            longest_run = 0;
        int            longest_p   = 9;
        int            cur_run     = 0;
        for (int i = 0; i < 8; i++) {
            digs[i] = ((unsigned short)(p[1]) << 8) | (unsigned short)(p[0]);
            if (digs[i] == 0) {
                cur_run++;
                if ((cur_run > 1) && (cur_run > longest_run)) {
                    longest_run = cur_run;
                    longest_p   = i + 1 - cur_run;
                }
            } else
                cur_run = 0;

            p -= 2;
        }

        for (int i = 0; i < 8; i++) {
            if (i >= longest_p && i < longest_p + longest_run) {
                if (i == longest_p) {
                    if (i == 0)
                        m_buffer[m_len++] = ':';
                    m_buffer[m_len++] = ':';
                }
            } else {
                add_hex_ushort(digs[i]);
                if (i != 7)
                    m_buffer[m_len++] = ':';
            }
        }
    }

    inline void add_string_q(const char* p)
    {
        char c;
        while ((c = *p++)) {
            m_buffer[m_len++] = c;
        }
    }

    inline void add_attr_ipv4(unsigned int i)
    {
        add_string_q(m_diglut[(i >> 24)]);
        m_buffer[m_len++] = '.';
        add_string_q(m_diglut[(i >> 16) & 255]);
        m_buffer[m_len++] = '.';
        add_string_q(m_diglut[(i >> 8) & 255]);
        m_buffer[m_len++] = '.';
        add_string_q(m_diglut[(i >> 0) & 255]);
    }
    inline void add_hex_ushort(unsigned short v)
    {
        static const char lut[] = "0123456789abcdef";
        if (v & 0xf000) {
            m_buffer[m_len++] = lut[v >> 12];
            m_buffer[m_len++] = lut[(v >> 8) & 0xf];
            m_buffer[m_len++] = lut[(v >> 4) & 0xf];
            m_buffer[m_len++] = lut[v & 0xf];
            return;
        }
        if (v & 0xf00) {
            m_buffer[m_len++] = lut[(v >> 8) & 0xf];
            m_buffer[m_len++] = lut[(v >> 4) & 0xf];
            m_buffer[m_len++] = lut[v & 0xf];
            return;
        }
        if (v & 0xf0) {
            m_buffer[m_len++] = lut[(v >> 4) & 0xf];
            m_buffer[m_len++] = lut[v & 0xf];
            return;
        }
        m_buffer[m_len++] = lut[v & 0xf];
    }
};

extern Output g_output;

} // namespace packetq

#endif // __packetq_output_h
