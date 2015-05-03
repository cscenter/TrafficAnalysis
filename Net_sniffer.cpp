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
    filter_exp = *(new string("ip"));
};



Net_sniffer::Net_sniffer(char *device, string protocol, bool mode) {
    dev = (char *) malloc((sizeof(device)));
    strcpy(dev, device);
    filter_exp = protocol;
    is_live = mode;
};


void Net_sniffer::start_sniff(Working_classes* p){

    if ( dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            string reason("Couldn't find default device");
            reason += *(new string(errbuf));
            throw new Net_sniffer_exception(reason);
        }
    }
    if (is_live) {
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1 && is_live) {
            string reason("Couldn't get netmask for device ");
            reason += *(new string(errbuf));
            throw new Net_sniffer_exception(reason);
        }
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    }
    else {
        handle = pcap_open_offline(dev, errbuf);
    }
    if (handle == NULL) {
        string reason("Couldn't open device ");
        reason += *(new string(errbuf));
        throw new Net_sniffer_exception(reason);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        string reason("It's not an Ethernet ");
        reason += *(new string(errbuf));
        throw new Net_sniffer_exception(reason);
    }
    cout << "Device " << dev << endl;
    cout << "Filter " << filter_exp.c_str() << endl;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 1, net) == -1) {
        //fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        throw new Net_sniffer_exception("Couldn't parse filter");
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        //fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        throw new Net_sniffer_exception("Couldn't install filte");
    }
    pcap_loop(handle, 0, got_packet, (u_char *)(p));
    pcap_freecode(&fp);
    pcap_close(handle);
};

void Net_sniffer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    Packet *value = new Packet();
    value->Parse(header, packet);
    if (!value->is_broken) {
        ((Working_classes *) args)->get_signature_analysis()->add_packet(value);
        //осторожно, я менял wc wc->get_statistic_analysys()->add_packet(*value);
    }
}

