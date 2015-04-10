#ifndef SESSION_H
#define SESSION_H
#include <pcap.h>
#include <string>
#include "Parse_packet.h"


struct Session {
    struct  in_addr ip_src;
    struct  in_addr ip_dst;
    u_short port_src;
    u_short port_dst;
    std::string prot;
    u_char protocol;
    int time_to_live;
    int last_packet_time;
    bool is_alive() const;
    void print_session();
    //EL: move to cpp
    bool operator < (const Session & b) const;
};

#endif