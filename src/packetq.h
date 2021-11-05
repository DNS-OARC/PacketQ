/*
 * Copyright (c) 2017-2021, OARC, Inc.
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

#ifndef __packetq_packetq_h
#define __packetq_packetq_h

#include "sql.h"

namespace packetq {

// App class
class PacketQ {
public:
    enum OutputOpts {
        json,
        csv,
        csv_format,
        xml
    };
    PacketQ()
    {
        m_escape = false;
        m_limit  = 0;
        m_output = json;
    }
    void set_escape(bool escape)
    {
        m_escape = escape;
    }
    void set_limit(int limit)
    {
        m_limit = limit;
    }
    void set_output(OutputOpts opt)
    {
        m_output = opt;
    }
    int        get_escape() { return m_escape; }
    OutputOpts get_output() { return m_output; }
    int        get_limit() { return m_limit; }

private:
    bool       m_escape;
    int        m_limit;
    OutputOpts m_output;
};

extern PacketQ* g_app;

} // namespace packetq

#endif // __packetq_packetq_h
