#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <arpa/inet.h>
#include <vector>
#include <string>

#include "Class_Parse_packet.h"

using namespace std;


struct Session {
    struct  in_addr ip_src;
    struct  in_addr ip_dst;
    u_short port_src;
    u_short port_dst;
    std::string prot;
    u_char protocol;
    //time?

    void PrintSession();

    //EL: move to cpp
    bool operator < (const Session & b) const;
};



struct allPackets {
     std::vector<SplitPacket> v;

     void PrintVector();
};

class NetSniffer {
	char *dev;				    // device name
	char errbuf[PCAP_ERRBUF_SIZE];		// error buffer
	pcap_t *handle;				// packet capture handle
	char *filter_exp;			// filter expression
	struct bpf_program fp;		// compiled filter program (expression)
	bpf_u_int32 mask;			// subnet mask
	bpf_u_int32 net;			// ip
	int num_packets;			// number of packets to capture
public:

	NetSniffer();

	int get();

	NetSniffer(char *device, char *protocol, int n);

	allPackets StartSniff();

    //EL move to cpp
	static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
};

#endif
