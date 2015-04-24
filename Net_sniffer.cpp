#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <time.h>
#include <stdlib.h>
#include "Net_sniffer.h"


using namespace std;

Net_sniffer::Net_sniffer() {
    strcpy(dev, "");
    is_live = true;
    strcpy(filter_exp, "ip");
};



Net_sniffer::Net_sniffer(char *device, char *protocol, bool mode) {
    //классу нужен деструктор
    dev = (char *) malloc((sizeof(device)));
    strcpy(dev, device);
    strcpy(filter_exp, protocol);
    is_live = mode;
};


void Net_sniffer::start_sniff(Working_classes* p){

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
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1 && is_live) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("Device: %s\n", dev);
    printf("Filter expression: %s\n\n\n", filter_exp);

    if (is_live) {
        handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
    }
    else {
        handle = pcap_open_offline(dev, errbuf);
    }
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    // compile the filter expression
    /*if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }*/

    pcap_loop(handle, 0, got_packet, (u_char *)(p));
    pcap_freecode(&fp);
    pcap_close(handle);
};

void Net_sniffer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    Working_classes * wc = (Working_classes *) args;
    Packet *value = new Packet();
    value->Parse(header, packet);
    if (!value->is_broken) {
        wc->get_signature_analysis()->add_packet(*value);
        //осторожно, я менял wc wc->get_statistic_analysys()->add_packet(*value);
    }
}

