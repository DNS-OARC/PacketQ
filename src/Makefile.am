AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = packetq 

packetq_SOURCES = segzip.h output.h packet_handler.h tcp.h sql.h packetq.h packet_handler.cpp packetq.cpp tcp.cpp sql.cpp pcap.h pcap.cpp reader.h reader.cpp server.h server.cpp dns.cpp dns.h icmp.cpp icmp.h MurmurHash3.cpp MurmurHash3.h refcountstring.h variant.h

if WITH_GEOIP
packetq_SOURCES += geo.cpp geo.h
endif

AM_CXXFLAGS = -std=c++0x -Wall -Wno-parentheses -Wno-switch -Wno-sign-compare -Wno-char-subscripts
