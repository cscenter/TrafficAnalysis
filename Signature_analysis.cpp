#include <iostream>
#include "Session.h"
#include "Signature_analysis.h"

using namespace std;

Pack_data::Pack_data() {
}

void Pack_data::to_upload(const Packet& pack) {
    //EL где деструктор?
    //u_char *value = new u_char[pack.get_size_payload()];
    //memmove(value, pack.get_pload(), pack.get_size_payload());
    upload.push_back(pack);
}

void Pack_data::to_download(const Packet& pack) {
    //u_char *value = new u_char[pack.get_size_payload()];
    //memmove(value, pack.get_pload(), pack.get_size_payload());
    download.push_back(pack);
}


int Pack_data::checking_for_signatures(const char *expr) {
    int count = 0;
    int i;
    //EL minor убрать дублирование кода
    cout << "UpLoad " << upload.size() << endl;
    for (i = 0; i < upload.size(); i++) {
        const char *payload = (char *)upload[i].get_pload();
        if ( strstr(payload, expr) != NULL) {
            count++;
        }
        //print_payload(strlen(payload), upload[i].get_pload());
        payload = NULL;
    }
    cout << "DownLoad " << download.size() << endl;
    for (i = 0; i < download.size(); i++) {
        const char *payload = (char *)download[i].get_pload();
        if ( strstr(payload, expr) != NULL ) {
            count++;
        }
        //print_payload(strlen(payload), download[i].get_pload());
        payload = NULL;
    }
    return count;
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

void Signature_analysis::print_sessions_list() {
    //EL в 11 стандарте есть auto
    map<Session, Pack_data>::iterator iter;
    iter = sessions_list.begin();
    while(iter != sessions_list.end()) {
        Session session = iter->first;
        session.print_session();
        Pack_data p_date = iter->second;

        //EL вывод на экран и принятие решения по сессии --- это совсем разные вещи
        char expr[] = "HTTP/1.1";
        int answer = p_date.checking_for_signatures(expr);
        if (answer) {
            cout << expr << "    " << "OK!!!" << "  " << answer << "  " << endl << endl;
        }
        else {
            cout << expr << "    " << "NONE!!!" << endl << endl;
        }
        iter++;
    }
}

/*void Signature_analysis::form_map(vector<Split_packet> Packets) {
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
}*/

void Signature_analysis::add_packet(const Packet& pack) {
    //EL minor хорошо бы утсранить 2 find'а
    Session session(pack);
    map<Session, Pack_data>::iterator iter;
    iter = sessions_list.find(session);
    if (iter != sessions_list.end()) {
        sessions_list[session].to_upload(pack);
    }
    else {
        session.session_reverse(); // если уже есть -> добавить, если нет -> создать
        iter = sessions_list.find(session);
        if (iter != sessions_list.end()) {
            sessions_list[session].to_download(pack);
        }
        else {
            session.session_reverse();
            sessions_list[session].to_upload(pack);
        }
    }
}



