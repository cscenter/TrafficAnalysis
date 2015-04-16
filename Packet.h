#ifndef CLASS_PARSE_PACKET_H
#define CLASS_PARSE_PACKET_H

#include <pcap.h>
#include <string.h>
//
#include <netinet/in.h>

#include "Pack_headers_struct.h"


//EL хорошо бы совместить эти оба класса в один, чтобы поля хранились
//EL вместе с методами, которые с ними работают

//EL нужны деструкторы! есть new, но нет delete => memory leak


class Packet {
    pcap_pkthdr header;

    sniff_ethernet ethernet;

    sniff_ip ip;

    sniff_tcp tcp;

    sniff_udp udp;

    u_char *payload;

    int size_ip;

    int size_tcp;

    int size_payload;

    int size_udp;

public:

    Packet();

    bool is_broken;

    void Parse(const pcap_pkthdr *head, const u_char *packet);

    inline int get_size_payload() const {
        return size_payload;
    };

    inline u_char* get_pload() const {
        return payload;
    };
    
    pcap_pkthdr get_header() const;
    
    sniff_ip get_ip() const;
    
    sniff_tcp get_tcp() const;
    
    sniff_udp get_udp() const;
};

#endif // CLASS_PARSE_PACKET_H
