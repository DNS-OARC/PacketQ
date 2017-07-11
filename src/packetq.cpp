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

#include "config.h"

#include "packet_handler.h"
#include "packetq.h"
#include "pcap.h"
#include "reader.h"
#include "server.h"
#include "sql.h"

#include <algorithm>
#include <list>
#include <stack>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#ifndef WIN32
#include <getopt.h>
#include <signal.h>
#endif

#define NUM_QUERIES 32

namespace packetq {

static void usage(char* argv0, bool longversion)
{
    if (!longversion) {
        fprintf(stdout,
            "usage: %s [-vhjctxd] [-s stmt] [-l pkts] [-p port] [-w dir] [-r dir] [-m num] <pcapfile ...>\n",
            argv0);
        return;
    }

    fprintf(stdout,
        "usage: %s [options] pcapfile(s)...\n"
        /* -o                description                                             .*/
        "  --select statements |\n"
        "  -s statement      Set the SQL statement, can be given multiple times.\n"
        "  --limit packets |\n"
        "  -l packets        Set maximum number of packets to process, from all\n"
        "                    files and not per file.\n"
        "  --version | -v    Display version and exit.\n"
        "  --help | -h       Display this help.\n"
        "\n"
        "Output:\n"
        "  --json | -j       JSON (default)\n"
        "  --csv | -c        CSV\n"
        "  --table | -t      Text table\n"
        "  --xml | -x ]      XML\n"
        "\n"
        "Web Server:\n"
        "  --daemon | -d     Run web server in daemon mode.\n"
        "  --port number |\n"
        "  -p number         Set the port number to listen on.\n"
        "  --webroot dir |\n"
        "  -w dir            Set the root directory for the web content.\n"
        "  --pcaproot dir |\n"
        "  -r dir            Set the root for the PCAP files to make available.\n"
        "  --maxconn number |\n"
        "  -m number         Set the maximum number of concurrent connections.\n"
        "\n"
        "example> packetq --csv -s \"select count(*) as mycount, protocol from dns group by protocol;\" myfile.pcap\n"
        "\n"
        "Packet fields (available in all tables):\n"
        "  id, s, us, ether_type, src_addr, src_port, dst_addr, dst_port, protocol,\n"
        "  ip_ttl, ip_version, fragments\n"
        "\"dns\" table fields:\n"
        "  qname, aname, msg_id, msg_size, opcode, rcode, extended_rcode,\n"
        "  edns_version, z, udp_size, qd_count, an_count, ns_count, ar_count,\n"
        "  qtype, qclass, atype, aclass, attl, aa, tc, rd, cd, ra, ad, do, edns0, qr,\n"
        "  edns0_ecs, edns0_ecs_family, edns0_ecs_source, edns0_ecs_scope,\n"
        "  edns0_ecs_address\n"
        "\"icmp\" table fields:\n"
        "  type, code, echo_identifier, echo_sequence, du_protocol, du_src_addr,\n"
        "  du_dst_addr, desc\n",
        argv0);
}

#ifdef WIN32
// windows support is merely for development purposes atm
#define PACKAGE_STRING "packetq"
struct option {
    char* s;
    int args;
    int b;
    char c;
};

char* optarg = 0;
int optind = 1;

int getopt_long(int argc, char* argv[], const char* str, option* opt, int* option_index)
{
    while (optind < argc) {
        if (argv[optind][0] != '-')
            return -1;
        if (argv[optind][1] != '-') {
            int i = 0;
            while (opt[i].s != NULL) {
                if (opt[i].c == argv[optind][1]) {
                    optarg = argv[optind + opt[i].args];
                    optind += 1 + opt[i].args;
                    return opt[i].c;
                }
                i++;
            }
        }
        optind++;
    }
    return -1;
}

#endif

void sigproc(int sig)
{
    //ignore sig pipe
    signal(SIGPIPE, sigproc);
}

PacketQ* g_app = new PacketQ();

} // namespace packetq

using namespace packetq;

// The main funtion
int main(int argc, char* argv[])
{
    signal(SIGPIPE, sigproc);
    int port = 0;
    int limit = 0;
    int max_conn = 7;
    bool daemon = false;

    init_packet_handlers(); // set up tables

    std::string webroot = "", pcaproot = "";
    std::string queries[NUM_QUERIES] = {
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
    };
    int qcount = 0;

    while (1) {
        int option_index;
        struct option long_options[] = {
            { "select", 1, 0, 's' },
            { "limit", 1, 0, 'l' },
            { "maxconn", 1, 0, 'm' },
            { "webroot", 1, 0, 'w' },
            { "pcaproot", 1, 0, 'r' },
            { "port", 1, 0, 'p' },
            { "daemon", 0, 0, 'd' },
            { "csv", 0, 0, 'c' },
            { "json", 0, 0, 'j' },
            { "table", 0, 0, 't' },
            { "xml", 0, 0, 'x' },
            { "help", 0, 0, 'h' },
            { "version", 0, 0, 'v' },
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "w:r:s:l:p:hHdvcxtjm:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'v':
            fprintf(stdout, "%s\n", PACKAGE_STRING);
            exit(0);
            break;
        case 's':
            if (qcount < NUM_QUERIES) {
                queries[qcount++] = optarg;
            } else {
                fprintf(stderr, "Warning: can't handle more than %d separate query strings; discarding '%s'\n", NUM_QUERIES, optarg);
            }
            break;
        case 'c':
            g_app->set_output(PacketQ::csv);
            break;
        case 't':
            g_app->set_output(PacketQ::csv_format);
            break;
        case 'x':
            g_app->set_output(PacketQ::xml);
            break;
        case 'j':
            g_app->set_output(PacketQ::json);
            break;
        case 'd':
            daemon = true;
            break;
        case 'w':
            webroot = optarg;
            break;
        case 'r':
            pcaproot = optarg;
            break;
        case 'm':
            max_conn = atoi(optarg) + 1;
            if (max_conn < 2)
                max_conn = 2;
            break;
        case 'l':
            limit = atoi(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Unknown option: %c\n", c);
            usage(argv[0], false);
            return 1;
        case 'h':
            usage(argv[0], true);
            return 1;
        }
    }
    g_app->set_limit(limit);
    if (port > 0) {
        start_server(port, daemon, pcaproot, webroot, max_conn);
    }

    if (optind >= argc) {
        fprintf(stderr, "Missing input uri\n");
        usage(argv[0], false);
        return 1;
    }

    std::vector<std::string> in_files;

    while (optind < argc) {
        in_files.push_back(argv[optind]);
        optind++;
    }

    Reader reader(in_files, g_app->get_limit());

    if (g_app->get_output() == PacketQ::json) {
        printf("[\n");
    }
    for (int i = 0; i < qcount; i++) {
        char tablename[32];
        snprintf(tablename, 32, "result-%d", i);
        try {
            Query query(tablename, queries[i].c_str());
            query.parse();
            query.execute(reader);
            Table* result = query.m_result;

            switch (g_app->get_output()) {
            case (PacketQ::csv_format):
                if (result)
                    result->csv(true);
                break;
            case (PacketQ::csv):
                if (result)
                    result->csv();
                break;
            case (PacketQ::xml):
                if (result)
                    result->xml();
                break;
            case (PacketQ::json):
                if (result)
                    result->json(i < (qcount - 1));
                break;
            }
        } catch (Error& e) {
            printf("Error: %s\n", e.m_err.c_str());
            fflush(stdout);
            exit(1);
        } catch (...) {
            printf("Error: an unknown error has occured !\n");
            fflush(stdout);
        }
    }
    if (g_app->get_output() == PacketQ::json) {
        printf("]\n");
    }

    delete g_app;

    void destroy_packet_handlers();

    return 0;
}
