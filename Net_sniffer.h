#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H
#include <vector>
#include <string>
#include "Parse_packet.h"

using namespace std;


struct Session {
    struct  in_addr ip_src;
    struct  in_addr ip_dst;
    u_short port_src;
    u_short port_dst;
    std::string prot;
    u_char protocol;
    //time?

    void print_session();

    //EL: move to cpp
    bool operator < (const Session & b) const;
};



struct All_packets {
     std::vector<SplitPacket> v;

     void print_vector();
};

class Net_sniffer {
	char *dev;              // device name
    char *filter_exp;	    // filter expression
	char errbuf[PCAP_ERRBUF_SIZE];		// error buffer
	pcap_t *handle;				// packet capture handle
	struct bpf_program fp;		// compiled filter program (expression)
	bpf_u_int32 mask;			// subnet mask
	bpf_u_int32 net;			// ip
	int num_packets;			// number of packets to capture
public:
	Net_sniffer();

	Net_sniffer(char *device, char *protocol, int n);

	All_packets start_sniff();

    //EL move to cpp
	static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
};

#endif
