#ifndef CLASS_PARSE_PACKET_H
#define CLASS_PARSE_PACKET_H

#include <pcap.h>
#include <string.h>
//
#include <netinet/in.h>

#include "Pack_headers_struct.h"

struct Split_packet {
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
	bool is_broken;
};


class Parse_packet {
public:

	Parse_packet();

	Split_packet Parse(const struct pcap_pkthdr *head, const u_char *packet);
};

#endif // CLASS_PARSE_PACKET_H
