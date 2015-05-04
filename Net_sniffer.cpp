#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <time.h>
#include <stdlib.h>
#include "Net_sniffer.h"


using namespace std;

// Net_sniffer() : is_live(true), filter_exp("ip")
Net_sniffer::Net_sniffer() {
    strcpy(dev, "");
    is_live = true;
    // filter_exp = "ip";
    // filter_exp = string("ip");
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
            //EL: ???
            reason += *(new string(errbuf));
            //EL: throw Net_sniffer_exception(reason);

            //EL: и в остальных местах тоже
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

        // throw Net_sniffer_exception(string("Couldn't open device ") + errbuf);
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
        throw new Net_sniffer_exception("Couldn't install filter");
    }
    pcap_loop(handle, 0, got_packet, (u_char *)(p));
    pcap_freecode(&fp);
    pcap_close(handle);
};

void Net_sniffer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    Packet *pack = new Packet();
    //EL: Parse code convention?
    pack->Parse(header, packet);
    if (!pack->is_broken) {
        //Working_classes *wc = (Working_classes*) args;
        //wc->get..
        ((Working_classes *) args)->get_statistic_analysys()->add_packet(pack);
        ((Working_classes *) args)->get_signature_analysis()->add_packet(pack);

    }
    //delete pack;
}

