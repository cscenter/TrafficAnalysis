#include <pcap.h>
#include <iostream>
#include <stdlib.h>
#include "Net_sniffer.h"


using namespace std;


Net_sniffer::Net_sniffer() : is_live(true), filter_exp("ip") {
    strcpy(dev, "");
}


Net_sniffer::Net_sniffer(const char *device, const string& protocol, bool mode) : filter_exp(protocol), is_live(mode) {
    strcpy(dev, device);
}


void Net_sniffer::start_sniff(Working_classes* p) {
    if (dev == NULL) {
        char *device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            string reason("Couldn't find default device ");
            throw Net_sniffer_exception(reason + errbuf);
            return;
        }
        strcpy(dev, device);
    }
    if (is_live) {
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1 && is_live) {
            string reason("Couldn't get netmask for device ");
            throw Net_sniffer_exception(reason + errbuf);
        }
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    }
    else {
        handle = pcap_open_offline(dev, errbuf);
    }
    if (handle == NULL) {
        string reason("Couldn't open device ");
        throw Net_sniffer_exception(reason + errbuf);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        string reason("It's not an Ethernet ");
        throw Net_sniffer_exception(reason + errbuf);
    }
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 1, net) == -1) {
        throw Net_sniffer_exception("Couldn't parse filter");
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        throw Net_sniffer_exception("Couldn't install filter");
    }

    cout << "Device " << dev << endl;
    cout << "Filter " << filter_exp.c_str() << endl;

    pcap_loop(handle, 0, got_packet, (u_char *)(p));
    pcap_freecode(&fp);
    pcap_close(handle);
}

void Net_sniffer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    Working_classes *wc = (Working_classes *) args;
    Packet *pack = new Packet();
    pack->parse(header, packet);
    if (!pack->is_broken) {
        wc->get_statistic_analysys().add_packet(pack);
       // wc->get_signature_analysis().add_packet(pack);
    }
}

