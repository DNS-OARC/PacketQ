/*
 * Copyright (c) 2017-2020, OARC, Inc.
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

#ifndef __packetq_reader_h
#define __packetq_reader_h

#include <memory>
#include <stdio.h>
#include <vector>

#include "pcap.h"
#include "sql.h"

namespace packetq {

class Packet_handler;

// reading packet rows out of a list of files
class Reader {
public:
    Reader(std::vector<std::string> filenames, int max_packets)
        : packets_read(0)
    {
        this->filenames         = filenames;
        this->currently_reading = filenames.end();
        this->max_packets       = max_packets;
    }

    void seek_to_start();

    bool done();
    bool read_next(Packet_handler* handler, const std::vector<int>& columns, Row& destination_row, int skip_packets);

private:
    std::vector<std::string>::iterator currently_reading;

    std::vector<std::string>   filenames;
    int                        max_packets, packets_read;
    std::unique_ptr<Pcap_file> pcap;
};

} // namespace packetq

#endif // __packetq_reader_h
