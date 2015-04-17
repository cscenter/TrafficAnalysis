#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <time.h>
#include <stdlib.h>
#include "Net_sniffer.h"


using namespace std;

Net_sniffer::Net_sniffer() {
    dev = NULL;
    //strcpy(filter_exp,"\0ip");// недоработанный
    num_packets = 100;
};



Net_sniffer::Net_sniffer(char *device, char *protocol, int n, const char *m) {
    //EL change to static arrays или как минимум надо память освобождать
    //классу нужен деструктор
    dev = (char *) malloc((sizeof(device))); //размер не под указатель?
    strcpy(dev, device);
    filter_exp = (char *) malloc((sizeof(protocol)));
    strcpy(filter_exp, protocol);
    num_packets = n;
    mode = (char *) malloc((sizeof(m)));
    strcpy(mode, m);
};


Working_classes Net_sniffer::start_sniff(){

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
    if (strstr(mode, "offline") != NULL) {
        handle = pcap_open_offline(dev, errbuf);
    }
    else {
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    //EL сделать два варианта запуска без переписывания программмы: из файла или из устройства

    // make sure we're capturing on an Ethernet device [2]
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


    //EL не нужно лишних копирования при возврате этой переменной
    //EL надо передавать указатель из main
    Working_classes p;

    pcap_loop(handle, 10000, got_packet, (u_char *)(&p));

    pcap_freecode(&fp);
    pcap_close(handle);
    return p;
};

void Net_sniffer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    Working_classes * wc = (Working_classes *) args;
    //EL классы должны быть названы существительными, например, PacketParser
    //Split_packet value;
    Packet *value = new Packet();
    //EL нет смысла делать лишние копирования
    value->Parse(header, packet);
    if (!value->is_broken) {
        wc->sig_analysator.add_packet(*value);
        //wc->stat_analysator.add_packet(value);
    }
}

