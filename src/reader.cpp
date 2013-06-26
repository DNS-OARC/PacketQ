#include "reader.h"

#include "packet_handler.h"

void se::Reader::seek_to_start()
{
    currently_reading = filenames.begin();
    pcap.reset();
    packets_read = 0;
}

bool se::Reader::done()
{
    return (!pcap && currently_reading == filenames.end()) ||
        (max_packets > 0 && packets_read >= max_packets);
}

bool se::Reader::read_next(Packet_handler *handler, const std::vector<int> &columns, Row &destination_row, int skip_packets)
{
    bool filled_in_row = false;

    while (!filled_in_row and !done()) {
        // try opening pcap file
        if (!pcap && currently_reading != filenames.end()) {
            FILE *fp = fopen(currently_reading->c_str(), "rb");
            if (fp)
            {
                pcap.reset(new Pcap_file(fp, Pcap_file::TAKE_OVER_FP));

                if (!pcap->get_header())
                    pcap.reset();
            }

            if (!pcap)
                ++currently_reading;
        }

        // try reading a row
        if (pcap)
        {
            int len, s, us;
            unsigned char *data = pcap->get_packet(len, s, us);
            bool read_success = len && data;
            ++packets_read;     // we count all packets
            if (read_success)
            {
                Packet packet(data, len, s, us, packets_read, pcap->get_link_layer_type());
                Packet::ParseResult res = packet.parse(handler, columns, destination_row, skip_packets == 0);

                if (res == Packet::NOT_SAMPLED)
                    --skip_packets;

                filled_in_row = res == Packet::OK;
            }
            else {
                // last row in file
                pcap.reset();
                ++currently_reading;
            }
        }
    }

    return filled_in_row;
}
