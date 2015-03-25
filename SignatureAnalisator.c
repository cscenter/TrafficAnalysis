#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include "SignatureAnalisator.h"



PackData::PackData() {
}

void PackData::FormPackDate(Session session, SplitPacket pack) {
    //const char *s = pack.payload;
    //string payload = new string(s);
    src = session.ip_src;     // бред, надо перепроверить
    if (inet_ntoa(src) == inet_ntoa(pack.ip->ip_src)) {
        UpLoad.push_back(pack.payload);
    }
    else {
        DownLoad.push_back(pack.payload);
    }
}


SignatureAnalisator::SignatureAnalisator() {
}

void SignatureAnalisator::PrintMap() {
    map<Session, PackData>::iterator iter;
    iter = Map.begin();
    while(iter != Map.end()) {
        cout << inet_ntoa(iter->first.ip_src) << "   " << endl;
        iter++;
    }
}

void SignatureAnalisator::FormMap(vector<SplitPacket> Packets) {
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
    switch(pack.ip->ip_p) {
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

