#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H
#include <vector>
#include <string>
#include "Working_classes.h"



class Net_sniffer {
private:
    char *dev;              // device name
    char *filter_exp;        // filter expression
    char errbuf[PCAP_ERRBUF_SIZE];        // error buffer
    pcap_t *handle;                // packet capture handle
    struct bpf_program fp;        // compiled filter program (expression)
    bpf_u_int32 mask;            // subnet mask
    bpf_u_int32 net;            // ip
    int num_packets;            // number of packets to capture
public:
    Net_sniffer();

    Net_sniffer(char *device, char *protocol, int n);

    Working_classes start_sniff();

    //EL move to cpp
    static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
};

#endif
