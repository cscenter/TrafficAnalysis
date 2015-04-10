#include <iostream>

#include "Signature_analysis.h"

using namespace std;

Pack_data::Pack_data() {
}


void Pack_data::form_pack_date(Session session, Split_packet pack) {
    src = session.ip_src;     // бред, надо перепроверить
    u_char *value = new u_char[pack.size_payload];
    memmove(value, pack.payload, pack.size_payload);

    if (src.s_addr == pack.ip.ip_src.s_addr) {
        upload.push_back(value);
    }
    else {
        download.push_back(value);
    }
}


int Pack_data::check_date(const char *expr) {
    int count = 0;
    int i;
    for (i = 0; i < upload.size(); i++) {
        const char *payload = (char *)upload[i];
        if ( strstr(payload, expr) != NULL) {
            count++;
        }
        print_payload(strlen(payload), upload[i]);
        payload = NULL;
    }
    for (i = 0; i < download.size(); i++) {
        const char *payload = (char *)download[i];
        if ( strstr(payload, expr) != NULL ) {
            count++;
        }
        print_payload(strlen(payload), download[i]);
        payload = NULL;
    }
    if (count) {
        return count;
    }
    return 0;
}

void Pack_data::print_payload(int length, const u_char *payload) {
    int i;
    while(length > 0) {
        int T = 40;
        if ( length < T) {
            for (i = 0; i < length; i++) {
                if (isprint(*payload)) {
                cout << *payload;
                }
                else {
                    cout << "." ;
                }
                payload++; // problem
            }
        }
        length -= T;
        while (T > 0) {
            if (isprint(*payload)) {
                cout << *payload;
            }
            else {
                cout << "." ;
            }
            payload++;
            T--;
        }
        cout << endl;
    }
}


Signature_analysis::Signature_analysis() {
}

void Signature_analysis::print_map() {
    map<Session, Pack_data>::iterator iter;
    iter = Map.begin();
    while(iter != Map.end()) {
        Session session = iter->first;
        session.print_session();
        Pack_data p_date = iter->second;
        char expr[] = "HTTP/1.1";
        int answer = p_date.check_date(expr);
        if (answer) {
            cout << expr << "    " << "OK!!!" << "  " << answer << "  " << endl << endl;
        }
        else {
            cout << expr << "    " << "NONE!!!" << endl << endl;
        }
        iter++;
    }
}

void Signature_analysis::form_map(vector<Split_packet> Packets) {
    int i;
    for (i = 0; i < Packets.size(); i++) {
        Session session = get_session(Packets[i]);
        Map[session].form_pack_date(session, Packets[i]);
    }
}

void Signature_analysis::add_packet(Split_packet pack) {
    Session session = get_session(pack);
    Map[session].form_pack_date(session, pack);
}

Session Signature_analysis::get_session(Split_packet pack) {
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

