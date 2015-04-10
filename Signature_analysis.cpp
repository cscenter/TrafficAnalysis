#include <iostream>
#include "Session.h"
#include "Signature_analysis.h"

using namespace std;

Pack_data::Pack_data() {
}

void Pack_data::to_upload(Split_packet pack) {
    u_char *value = new u_char[pack.size_payload];
    memmove(value, pack.payload, pack.size_payload);
    upload.push_back(value);
}

void Pack_data::to_download(Split_packet pack) {
    u_char *value = new u_char[pack.size_payload];
    memmove(value, pack.payload, pack.size_payload);
    download.push_back(value);
}


int Pack_data::check_date(const char *expr) {
    int count = 0;
    int i;
    cout << "UpLoad " << upload.size() << endl;
    for (i = 0; i < upload.size(); i++) {
        const char *payload = (char *)upload[i];
        if ( strstr(payload, expr) != NULL) {
            count++;
        }
        //print_payload(strlen(payload), upload[i]);
        payload = NULL;
    }
    cout << "DownLoad " << download.size() << endl;
    for (i = 0; i < download.size(); i++) {
        const char *payload = (char *)download[i];
        if ( strstr(payload, expr) != NULL ) {
            count++;
        }
        //print_payload(strlen(payload), download[i]);
        payload = NULL;
    }
    if (count) {
        return count;
    }
    return 0;
}

void Pack_data::print_payload(int length, const u_char *payload) { // вывод полезной нагрузки пакетов
    int i;
    while(length > 0) {
        int T = 100; // длина выводимой строки
        if (length < T) {
            for (i = 0; i < length; i++) {
                if (isprint(*payload)) {
                    cout << *payload;
                }
                else {
                    cout << "." ;
                }
                payload++;
                length--;
            }
            T = 0;
            cout << endl;
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
    cout << endl;
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
    map<Session, Pack_data>::iterator iter;
    for (i = 0; i < Packets.size(); i++) {
        Session session = get_session(Packets[i]);
        iter = Map.find(session);
        if (iter != Map.end()) {
            Map[session].to_upload(Packets[i]);
        }
        else {
            session.session_reverse(); // если уже есть -> добавить, если нет -> создать
            iter = Map.find(session);
            if (iter != Map.end()) {
                Map[session].to_download(Packets[i]);
            }
            else {
                session.session_reverse(); // вопрос
                Map[session].to_upload(Packets[i]);
            }
        }
    }
    //cout << Map.size() << endl;
}

void Signature_analysis::add_packet(const Split_packet& pack) {
    Session session = get_session(pack);
    map<Session, Pack_data>::iterator iter;
    iter = Map.find(session);
    if (iter != Map.end()) {
        Map[session].to_upload(pack);
    }
    else {
        session.session_reverse(); // если уже есть -> добавить, если нет -> создать
        iter = Map.find(session);
        if (iter != Map.end()) {
            Map[session].to_download(pack);
        }
        else {
            session.session_reverse();
            Map[session].to_upload(pack);
        }
    }
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

