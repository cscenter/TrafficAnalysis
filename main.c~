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

//#include "class_sniff.h"
#include "class_sniff.c"
#include "StatisticAnalysis.h"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define UDP_length 8

void PrintVector(SplitPacket &s_pack) {
		printf("From: %s\n", inet_ntoa(s_pack.ip->ip_src));
		printf("To: %s\n", inet_ntoa(s_pack.ip->ip_dst));

		switch(s_pack.ip->ip_p) {
			case IPPROTO_TCP:
				printf("Protocol: TCP\n");
				if (s_pack.size_tcp < 20) {
					printf("Invalid TCP header length: %u bytes\n", s_pack.size_tcp);
					return;
				}
				printf("Src port: %d\n", ntohs(s_pack.tcp->th_sport));
				printf("Dst port: %d\n", ntohs(s_pack.tcp->th_dport));

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
					return;
				}

				printf("Src port: %d\n", ntohs(s_pack.udp->s_port));
				printf("Dst port: %d\n", ntohs(s_pack.udp->d_port));

				if (s_pack.size_payload > 0) {
					printf("Payload (%d bytes):\n\n\n", s_pack.size_payload);
					//print_payload(payload, size_payload);
				}

				break;
			default:
				printf("Protocol: %c\n\n\n", s_pack.ip->ip_p );
				return;
		}
		return;
}



int main(int argc, char **argv) {
	char protocol[] = "ip";
    allPackets p;
	if (argc == 2) {
			NetSniffer *obj = new NetSniffer(argv[1], protocol, 10);
			p = obj->StartSniff();
	}
	else if (argc > 2) {
			fprintf(stderr, "error: unrecognized command-line options\n\n");
			exit(EXIT_FAILURE);
			}
	else {
		NetSniffer *obj = new NetSniffer();
        p = obj->StartSniff();
	}

	//cout << "size of vector: " << p.v.size() << endl;
    int i;
    for (i = 0; i < p.v.size(); i++) {
        PrintVector(p.v[i]);
    }

    //StatisticAnalysis * statAnalysis = new StatisticAnalysis(p);
    printf("\nCapture complete.\n");

	return 0;
};
