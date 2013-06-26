#ifndef SEREADER_H
#define SEREADER_H

#include <memory>
#include <vector>
#include <stdio.h>
#include "pcap.h"
#include "sql.h"

namespace se
{
    class Packet_handler;

    // reading packet rows out of a list of files
    class Reader
    {
    public:
        Reader(std::vector<std::string> filenames, int max_packets, bool verbose)
        {
            this->filenames = filenames;
            this->currently_reading = filenames.end();
            this->max_packets = max_packets;
	    this->verbose = verbose;
        }

        void seek_to_start();

        bool done();
        bool read_next(Packet_handler *handler, const std::vector<int> &columns, Row &destination_row, int skip_packets);

    private:
        std::vector<std::string>::iterator currently_reading;

        std::vector<std::string> filenames;
        int max_packets, packets_read;
        std::unique_ptr<Pcap_file> pcap;
	bool verbose;
    };
}

#endif
