#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <stdlib.h>
#include "Net_sniffer.h"

using namespace std;

Net_sniffer::Net_sniffer() {
	dev = NULL;
	//strcpy(filter_exp,"\0ip");// недоработанный
	num_packets = 100;
};



Net_sniffer::Net_sniffer(char *device, char *protocol, int n) {
	//EL change to static arrays
	dev = (char *) malloc((sizeof(device)));
	strcpy(dev, device);
	filter_exp = (char *) malloc((sizeof(protocol)));
	strcpy(filter_exp, protocol);
	num_packets = n;
};

All_packets Net_sniffer::start_sniff(){

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

    All_packets p;

	pcap_loop(handle, num_packets, got_packet, (u_char *)(&p));

	pcap_freecode(&fp);
    pcap_close(handle);
    return p;
};

void Net_sniffer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    All_packets * pack = (All_packets *) args;
    Split_packet value;
    Parse_packet *obj = new Parse_packet();
    value = obj->Parse(header, packet);
    if (!value.is_broken) {
        pack -> v.push_back(value);
    }
}

void All_packets::print_vector() {
    int i;
    Split_packet s_pack;
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
                s_pack.size_udp = UDP_LENGTH;

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

bool Session::operator < (const Session & b) const {
    if (ip_src.s_addr != b.ip_src.s_addr) return ip_src.s_addr < b.ip_src.s_addr;
    if (ip_dst.s_addr != b.ip_dst.s_addr) return ip_dst.s_addr < b.ip_dst.s_addr;
    if (port_src != b.port_src) return port_src < b.port_src;
    if (port_dst != b.port_dst) return port_dst < b.port_dst;
    return protocol < b.protocol;
}
//operator<<
void Session::print_session(){
    cout << "From ip:   " << inet_ntoa(ip_src) << endl;
    cout << "To ip:     " << inet_ntoa(ip_dst) << endl;
    cout << "From port: " << ntohs(port_src) << endl;
    cout << "To port:   " << ntohs(port_dst) << endl;
    cout << "Protocol   " << prot << endl;
    cout << endl;
}
