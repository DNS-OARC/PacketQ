#ifndef SEREADER_H
#define SEREADER_H

#include <memory>
#include <vector>
#include <stdio.h>
#include "pcap.h"
#include "sql.h"

namespace se 
{
    // reading packet rows out of a list of files
    class Reader
    {
    public:
        Reader(std::vector<std::string> filenames, int max_packets)
        {
            this->filenames = filenames;
            this->currently_reading = filenames.end();
            this->max_packets = max_packets;
        }

        void seek_to_start();

        bool done();
        bool read_next(const std::string &application_protocol, Row &destination_row);

    private:
        void open_pcap(std::string);

        std::vector<std::string>::iterator currently_reading;

        std::vector<std::string> filenames;
        int max_packets, packets_read;
        std::unique_ptr<Pcap_file> pcap;
    };
}

#endif
