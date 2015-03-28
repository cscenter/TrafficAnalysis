//#include <time.h>
//#include <ctype.h>
//#include <errno.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <map>



#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>
#include <arpa/inet.h>
#include <vector>
#include <string>


#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define UDP_length 8

using namespace std;

#ifndef class_sniff_h
#define class_sniff_h

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;                     // IP? ARP? RARP? etc
};


struct sniff_ip {
        u_char  ip_vhl;                 // version << 4 | header length >> 2
        #define IP_HL(ip)               (((s_pack->ip)->ip_vhl) & 0x0f)
        #define IP_V(ip)                (((s_pack->ip)->ip_vhl) >> 4)
        u_char  ip_tos;                 // type of service
        u_short ip_len;                 // total length
        u_short ip_id;                  // identification
        u_short ip_off;                 // fragment offset field
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;                 // time to live
        u_char  ip_p;                   // protocol
        u_short ip_sum;
        struct  in_addr ip_src,ip_dst;
};

typedef u_int tcp_seq;

struct sniff_udp {
	u_short s_port;
	u_short d_port;
	u_short length;
	u_short k_sum;
};

struct sniff_tcp {
        u_short th_sport;               // source port
        u_short th_dport;               // destination port
        tcp_seq th_seq;                 // sequence number
        tcp_seq th_ack;                 // acknowledgement number
        u_char  th_offx2;               // data offset, rsvd
        #define TH_OFF(tcp)      (((s_pack->tcp)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};


struct SplitPacket {
	struct pcap_pkthdr header;
	struct sniff_ethernet ethernet;
	struct sniff_ip ip;
	struct sniff_tcp tcp;
	struct sniff_udp udp;
	u_char *payload;
	int size_ip;
	int size_tcp;
	int size_payload;
	int size_udp;
	bool flag;
};



class ParsePacket {
public:

	ParsePacket();

	SplitPacket Parse(const struct pcap_pkthdr *head, const u_char *packet);
};



struct Session {
    struct  in_addr ip_src;
    struct  in_addr ip_dst;
    u_short port_src;
    u_short port_dst;
    string prot;
    u_char protocol;
    //time?

    void PrintSession();

    bool operator < (const Session & b) const {
        if (ip_src.s_addr != b.ip_src.s_addr) return ip_src.s_addr < b.ip_src.s_addr;
	if (ip_dst.s_addr != b.ip_dst.s_addr) return ip_dst.s_addr < b.ip_dst.s_addr;
	if (port_src != b.port_src) return port_src < b.port_src;
	if (port_dst != b.port_dst) return port_dst < b.port_dst;
	return protocol < b.protocol;
	}
};



struct allPackets {
     vector<SplitPacket> v;

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

	static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
		allPackets * pack = (allPackets *) args;
		SplitPacket value;
		ParsePacket *obj = new ParsePacket();
		value = obj->Parse(header, packet);
		if (value.flag) {
            pack -> v.push_back(value);
        }
	}
};

#endif
