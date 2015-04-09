#include <iostream>

#include "Signature_analysis.h"

using namespace std;

PackData::PackData() {
}


void PackData::FormPackDate(Session session, Split_packet pack) {
    src = session.ip_src;     // бред, надо перепроверить
    u_char *value = new u_char[pack.size_payload];
    memmove(value, pack.payload, pack.size_payload);

    if (src.s_addr == pack.ip.ip_src.s_addr) {
        UpLoad.push_back(value);
    }
    else {
        DownLoad.push_back(value);
    }
}

//EL const
int PackData::CheckDate(const char *expr) {
    int count = 0;
    int i;
    //const char *exp = (char *)expr;
    for (i = 0; i < UpLoad.size(); i++) {
        const char *payload = (char *)UpLoad[i];
        if ( !strstr(payload, expr) ) {
            count++;
        }
        payload = NULL;
    }
    for (i = 0; i < DownLoad.size(); i++) {
        const char *payload = (char *)DownLoad[i];
        if ( !strstr(payload, expr) ) {
            count++;
        }
        payload = NULL;
    }
    if (count) {
        return count;
    }
    return 0;
}


Signature_analysis::Signature_analysis() {
}

void Signature_analysis::PrintMap() {
    map<Session, PackData>::iterator iter;
    iter = Map.begin();
    while(iter != Map.end()) {
        Session session = iter->first;
        session.print_session();
        PackData p_date = iter->second;
        char expr[] = "HTTP/1.1";
        int answer = p_date.CheckDate(expr);
        if (answer) {
            cout << expr << "    " << "OK!!!" << "  " << answer << "  " << endl << endl;
        }
        else {
            cout << expr << "    " << "NONE!!!" << endl << endl;
        }
        iter++;
    }
}

void Signature_analysis::FormMap(vector<Split_packet> Packets) {
    int i;
    for (i = 0; i < Packets.size(); i++) {
        Session session = GetSession(Packets[i]);
        Map[session].FormPackDate(session, Packets[i]);
    }
}

Session Signature_analysis::GetSession(Split_packet pack) {
    Session session;
    session.ip_src = pack.ip.ip_src;
    session.ip_dst = pack.ip.ip_dst;
    session.protocol = pack.ip.ip_p;
    switch(pack.ip.ip_p) {
        case IPPROTO_TCP:
            session.port_src = pack.tcp.th_sport;
            session.port_dst = pack.tcp.th_dport;
            session.prot = "TCP";
            break;
        case IPPROTO_UDP:
            session.port_src = pack.udp.s_port;
            session.port_dst = pack.udp.d_port;
            session.prot = "UDP";
            break;
    }
    return session;
}

