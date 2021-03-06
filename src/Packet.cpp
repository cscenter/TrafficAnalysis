#include <stdlib.h>
#include "Packet.h"
using namespace std;

Packet::Packet() {

};

Packet::Packet(const Packet& pack) {
    header = pack.header;
    ethernet = pack.ethernet;
    ip = pack.ip;
    tcp = pack.tcp;
    udp = pack.udp;
    payload = new u_char[pack.size_payload];
    memcpy(payload, pack.payload, pack.size_payload);
    size_ip = pack.size_ip;
    size_tcp = pack.size_tcp;
    size_payload = pack.size_payload;
    size_udp = pack.size_udp;
};

void Packet::parse(const struct pcap_pkthdr *head, const u_char *packet) {
    header = *head;
    //int size_pack = sizeof(*pack);
    //u_char *packet = new u_char[size_pack + 1];
    //memcpy(packet, pack, size_pack + 1);

    ethernet = *(sniff_ethernet*)packet;
    ip = *(sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = (((ip).ip_vhl) & 0x0f)*4;
    if (size_ip < 20) {
        is_broken = true;
        return;
    }
    //EL minor можно повторяющийся код написать один раз, например,
    //вынести его в отдельную функцию
    switch(ip.ip_p) {
        case IPPROTO_TCP:
            is_broken = false;
            tcp = *(sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = (((tcp).th_offx2 & 0xf0) >> 4) * 4;

            if (size_tcp < 20) {
                return;
            }
            size_payload = ntohs(ip.ip_len) - (size_ip + size_tcp);
            payload = new u_char[size_payload];
            memcpy(payload, ( (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp) ), size_payload);
            break;
        case IPPROTO_UDP:
            is_broken = false;
            udp = *(sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            size_udp = UDP_LENGTH;

            if (size_udp < 8) {
                is_broken = true;
                return;
            }
            size_payload = ntohs(ip.ip_len) - (size_ip + size_udp);
            payload = new u_char[size_payload];
            memmove(payload,(u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp), size_payload);
            break;
        default:
            is_broken = true;
            return;
    }
    return;
};



pcap_pkthdr Packet::get_header() const {
    return header;
}


sniff_ip Packet::get_ip() const {
    return ip;
}

sniff_tcp Packet::get_tcp() const {
    return tcp;
}

sniff_udp Packet::get_udp() const {
    return udp;
}
