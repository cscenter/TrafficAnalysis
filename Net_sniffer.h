#ifndef NET_SNIFFER_H
#define NET_SNIFFER_H
//EL хэдеры лучше включать там, где они нужны
#include <vector>
#include <string>
#include "Working_classes.h"



class Net_sniffer {
private:
    char *dev;              // device name
    bool is_live;
    char filter_exp[10];        // filter expression
    char errbuf[PCAP_ERRBUF_SIZE];        // error buffer
    pcap_t *handle;                // packet capture handle
    bpf_program fp;        // compiled filter program (expression)
    bpf_u_int32 mask;            // subnet mask
    bpf_u_int32 net;            // ip
public:
    Net_sniffer();
    Net_sniffer(char *device, char *protocol, bool mode);
    ~Net_sniffer() { delete dev; }

    void start_sniff(Working_classes *p);

    static void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet);
};

#endif
