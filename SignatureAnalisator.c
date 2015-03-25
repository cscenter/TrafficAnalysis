#include <pcap.h>
//#include <stdio.h>
#include <string.h>
//#include <stdlib.h>
//#include <iostream>
//#include <new>

//#include <ctype.h>
//#include <errno.h>
//#include <sys/types.h>
//#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include "SignatureAnalisator.h"



void PackData::PackData() {
}

void PackData::FormPackDate(Session session, SplitPacket pack) {
    string payload = new string(pack->payload);
    src = session.ip_src;     // бред, надо перепроверить
    if (inet_aton(src) == inet_aton(pack.ip->ip_src)) {
        UpLoad.push_back(payload);
    }
    else {
        DownLoad.push_back(payload);
    }
}


SignatureAnalisator::SignatureAnalisator() {
}

void SignatureAnalisator::FormMap(vector <SplitPacket> Packets) {
    int i;
    for (i = 0; i < Packets.size(); i++) {
        Session session = GetSession(Packets[i]);
        Map[session].FormPackDate(session, Packets[i]);
    }
}

Session SignatureAnalisator::GetSession(SplitPacket pack) {
    Session session;
    session.ip_src = pack.ip->ip_src;
    session.ip_dst = pack.ip->ip_dst;
    session.protocol = pack.ip->ip_p;
    switch(s_pack->ip->ip_p) {
        case IPPROTO_TCP:
            session.port_src = pack.tcp->th_sport;
            session.port_dst = pack.tcp->th_dport;
            break;
        case IPPROTO_UDP:
            session.port_src = pack.udp->s_port;
            session.port_dst = pack.udp->d_port;
            break;
    }
}

