/*
 Copyright (c) 2011, .SE - The Internet Infrastructure Foundation
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgement:
    This product includes software developed by the .SE - The Internet 
    Infrastructure Foundation.
 4. Neither the name of .SE - The Internet Infrastructure Foundation nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY .SE - THE INTERNET INFRASTRUCTURE FOUNDATION 
 ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL .SE - The Internet Infrastructure Foundation
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
 WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <stack>
#include <algorithm>
#include <stdexcept>
#ifndef WIN32
#include <signal.h>
#include <getopt.h>
#include "../config.h"
#endif
#include "packet_handler.h"
#include "sql.h"
#include "packetq.h"
#include "pcap.h"
#include "server.h"
#include "reader.h"

#define NUM_QUERIES	32

namespace se {

static void usage ( char * argv0, bool longversion ) {
   fprintf (stdout, "usage: %s [ --select | -s select-statement ] [ --port | -p httpportnumber ] [ --json | -j ] [ --csv | -c ] [ --table | -t ] [ --xml | -x ] [ --daemon | -d ] [ --webroot | -w webdir ] [ --pcaproot | -r pcapdir ] [ --help | -h ] [ --limit | -l ] [ --maxconn | -m ] pcapfile(s)...\n", argv0);
   if (!longversion)
       return;

   fprintf (stdout, "\n    sample:\n> packetq --csv -s \"select count(*) as mycount,protocol from dns group by protocol;\" myfile.pcap\n");
   fprintf (stdout, "\n" \
		    "    column names for use in the sql statements:\n\n" \
		    "      qname\n" \
		    "      aname\n" \
		    "      msg_id\n" \
		    "      msg_size\n" \
		    "      opcode\n" \
		    "      rcode\n" \
		    "      extended_rcode\n" \
		    "      edns_version\n" \
		    "      z\n" \
		    "      udp_size\n" \
		    "      qd_count\n" \
		    "      an_count\n" \
		    "      ns_count\n" \
		    "      ar_count\n" \
		    "      qtype\n" \
		    "      qclass\n" \
		    "      atype\n" \
		    "      aclass\n" \
		    "      attl\n" \
		    "      aa\n" \
		    "      tc\n" \
		    "      rd\n" \
		    "      cd\n" \
		    "      ra\n" \
		    "      ad\n" \
		    "      do\n" \
		    "      edns0\n" \
		    "      qr\n");

}

#ifdef WIN32
// windows support is merely for development purposes atm
#define PACKAGE_STRING "packetq"
struct option
{
    char    *s;
    int     args;
    int     b;
    char    c;
};

char *optarg = 0;
int   optind = 1;

int getopt_long (int argc, char * argv[], const char *str, option *opt, int *option_index)
{
    while (optind < argc) 
    {
    if (argv[optind][0]!='-')
	return -1;
    if (argv[optind][1]!='-')
    {
	int i=0;
	while(opt[i].s != NULL)
	{
	if (opt[i].c==argv[optind][1])
	{
	    optarg = argv[optind+opt[i].args];
	    optind+=1+opt[i].args;
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

PacketQ *g_app = new PacketQ();

} // end se namespace

using namespace se;

// The main funtion
int main (int argc, char * argv []) 
{
    signal(SIGPIPE, sigproc);
    int port	= 0;
    int limit	= 0;
    int max_conn= 7;
    bool daemon = false;

    init_packet_handler();  // set up tables

    std::string webroot="",pcaproot="";
    std::string query[NUM_QUERIES] = {"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", };
    int qcount = 0;

    while (1) 
    {
	int option_index;
	struct option long_options [] = 
	{
	    {"select",	1, 0, 's'},
	    {"limit",	1, 0, 'l'},
	    {"maxconn", 1, 0, 'm'},
	    {"webroot", 1, 0, 'w'},
	    {"pcaproot",1, 0, 'r'},
	    {"port",	1, 0, 'p'},
	    {"daemon",	0, 0, 'd'},
	    {"csv",	0, 0, 'c'},
	    {"json",	0, 0, 'j'},
	    {"table",	0, 0, 't'},
	    {"xml",	0, 0, 'x'},
	    {"help",	0, 0, 'h'},
	    {"version", 0, 0, 'v'},
	    {NULL,  0, 0, 0}
	};

	int c = getopt_long (argc, argv, "w:r:s:l:p:hHdvcxtjm:", long_options, &option_index);
	if (c == -1)
	    break;

	switch (c) {
	    case 'v':
		fprintf (stdout, "%s\n", PACKAGE_STRING ); 
		exit (0);
		break;
	    case 's':
		if (qcount < NUM_QUERIES) {
		    query[qcount++] = optarg;
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
		max_conn = atoi(optarg)+1;
		if (max_conn<2)
		    max_conn = 2;
		break;
	    case 'l':
		limit = atoi(optarg);
		break;
	    case 'p':
		port = atoi(optarg);
		break;
	    default:
		fprintf (stderr, "Unknown option: %c\n", c);
		usage (argv [0],false);
		return 1;
	    case 'h':
		usage (argv [0],true);
		return 1;
	}
    }
    g_app->set_limit(limit);
    if (port>0)
    {
	start_server( port, daemon, webroot, pcaproot, max_conn );	
    }

    if (optind >= argc) {
	fprintf (stderr, "Missing input uri\n");
	usage (argv [0],false);
	return 1;
    }

    try
    {
	// pass 1 make sure we read out sample
	Query q;
	q.ask( query[0].c_str(), true );
	g_app->set_sample( q.get_sample() );
    }
    catch(Error &e)
    {
	printf( "Error: %s\n", e.m_err.c_str() );
	fflush( stdout );
	exit(1);
    }
    catch(...)
    {
    }

    std::vector<std::string> in_files;

    while (optind < argc)
    {
        in_files.push_back(argv[optind]);
	optind++;
    }

    Reader reader(in_files, g_app->get_limit());

    if ( g_app->get_output() == PacketQ::json ) {
	printf("[\n");
    }
    for (int i=0; i < qcount; i++ ) {
	char tablename[32];
	snprintf(tablename, 32, "result-%d", i);
	try
	{
	    // pass 2 now all tables are in place and the query can be properly analyzed
	    g_app->new_query(tablename, query[i].c_str());
	    g_app->m_query->ask( query[i].c_str() );
	}
	catch(Error &e)
	{
	    printf( "Error: %s\n", e.m_err.c_str() );
	    fflush( stdout );
	    exit(1);
	}
	catch(...)
	{
	    printf( "Error: an unknown error has occured !\n" );
	    fflush( stdout );
	}

	g_app->m_query->execute(reader);
	Table *result = g_app->m_query->get_result();

	switch( g_app->get_output() )
	{
	    case( PacketQ::csv_format ):
		{
		    if (result)
			result->csv(true);
		}
		break;
	    case( PacketQ::csv ):
		{
		    if (result)
			result->csv();
		}
		break;
	    case( PacketQ::xml ):
		{
		    if (result)
			result->xml();
		}
		break;
	    case( PacketQ::json ):
		{
		    if (result)
			result->json(i<(qcount-1));
		}
		break;
	}
    }
    if ( g_app->get_output() == PacketQ::json ) {
	printf("]\n");
    }

    delete g_app;
    return 0;
}


