#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include <time.h>

#include "class_sniff.h"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define UDP_length 8

using namespace std;


ParsePacket::ParsePacket() {
};

SplitPacket ParsePacket::Parse(const struct pcap_pkthdr *head, const u_char *packet) {
	SplitPacket s_pack;
	s_pack.header = *head;
	s_pack.ethernet = *(sniff_ethernet*)packet;
	s_pack.ip = *(sniff_ip *)(packet + SIZE_ETHERNET);
	s_pack.size_ip = (((s_pack.ip).ip_vhl) & 0x0f)*4;
	if (s_pack.size_ip < 20) {
        s_pack.flag = false;
		return s_pack;
	}
	switch(s_pack.ip.ip_p) {
		case IPPROTO_TCP:
			s_pack.flag = true;
			s_pack.tcp = *(struct sniff_tcp*)(packet + SIZE_ETHERNET + s_pack.size_ip);
			s_pack.size_tcp = (((s_pack.tcp).th_offx2 & 0xf0) >> 4) * 4;

			if (s_pack.size_tcp < 20) {
                s_pack.flag = false;
				return s_pack;
			}
			s_pack.size_payload = ntohs(s_pack.ip.ip_len) - (s_pack.size_ip + s_pack.size_tcp);
			s_pack.payload = (u_char *) malloc(s_pack.size_payload * sizeof(u_char));
			memmove(s_pack.payload, ( (u_char *)(packet + SIZE_ETHERNET + s_pack.size_ip + s_pack.size_tcp) ), s_pack.size_payload);
			break;
		case IPPROTO_UDP:
			s_pack.flag = true;
			s_pack.udp = *(struct sniff_udp*)(packet + SIZE_ETHERNET + s_pack.size_ip); //как-то нужно ведь смотреть длину заголовка
			s_pack.size_udp = UDP_length;

			if (s_pack.size_udp < 8) {
                s_pack.flag = false;
				return s_pack;
			}
            s_pack.size_payload = ntohs(s_pack.ip.ip_len) - (s_pack.size_ip + s_pack.size_udp);
            s_pack.payload = (u_char *) malloc(s_pack.size_payload * sizeof(u_char));
			memmove(s_pack.payload,(u_char *)(packet + SIZE_ETHERNET + s_pack.size_ip + s_pack.size_udp), s_pack.size_payload);
			break;
		default:
			s_pack.flag = false;
			return s_pack;
	}
	return s_pack;
};



NetSniffer::NetSniffer() {
	dev = NULL;
	//strcpy(filter_exp,"\0ip");// недоработанный
	num_packets = 100;
};



NetSniffer::NetSniffer(char *device, char *protocol, int n) {
	dev = (char *) malloc((sizeof(device)));
	strcpy(dev, device);
	filter_exp = (char *) malloc((sizeof(protocol)));
	strcpy(filter_exp, protocol);
	num_packets = n;
};

allPackets NetSniffer::StartSniff(){

	if ( dev == NULL) {
		// find a capture device if not specified on command-line
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}

	// get network number and mask associated with capture device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n\n\n", filter_exp);

	// open capture device
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	//handle = pcap_open_offline(dev, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	// make sure we're capturing on an Ethernet device [2]
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	// compile the filter expression
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	// apply the compiled filter
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

    allPackets p;

	pcap_loop(handle, num_packets, got_packet, (u_char *)(&p));

	pcap_freecode(&fp);
    pcap_close(handle);
    return p;
};

void allPackets::PrintVector() {
    int i;
    SplitPacket s_pack;
    for (i = 0; i < v.size(); i++) {
        s_pack = v[i];
        printf("From: %s\n", inet_ntoa(s_pack.ip.ip_src));
        printf("To: %s\n", inet_ntoa(s_pack.ip.ip_dst));

        switch(s_pack.ip.ip_p) {
            case IPPROTO_TCP:
                printf("Protocol: TCP\n");

                if (s_pack.size_tcp < 20) {
                    printf("Invalid TCP header length: %u bytes\n", s_pack.size_tcp);
                }
                printf("Src port: %d\n", ntohs(s_pack.tcp.th_sport));
                printf("Dst port: %d\n", ntohs(s_pack.tcp.th_dport));

                if (s_pack.size_payload > 0) {
                    printf("Payload (%d bytes):\n\n\n", s_pack.size_payload);
                }
                else {
                cout << endl << endl;
                }
                break;
            case IPPROTO_UDP:
                printf("Protocol: UDP\n");
                s_pack.size_udp = UDP_length;

                if (s_pack.size_udp < 8) {
                    printf("Invalid UDP header length: %u bytes\n", s_pack.size_udp);
                }
                printf("Src port: %d\n", ntohs(s_pack.udp.s_port));
                printf("Dst port: %d\n", ntohs(s_pack.udp.d_port));

                if (s_pack.size_payload > 0) {
                    printf("Payload (%d bytes):\n\n\n", s_pack.size_payload);
                }
                break;
            default:
                printf("Protocol: %c\n\n\n", s_pack.ip.ip_p );
        }
    }
};

void Session::PrintSession(){
    cout << "From ip:   " << inet_ntoa(ip_src) << endl;
    cout << "To ip:     " << inet_ntoa(ip_dst) << endl;
    cout << "From port: " << ntohs(port_src) << endl;
    cout << "To port:   " << ntohs(port_dst) << endl;
    cout << "Protocol   " << prot << endl;
    cout << endl;
}
