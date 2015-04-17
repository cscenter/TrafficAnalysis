#include <iostream>
#include "Session.h"
#include "Signature_analysis.h"

using namespace std;

Session_data::Session_data() {
    solution = false;
    session_solution = "";
}

void Session_data::to_upload(const Packet& pack) {
    upload.push_back(pack);
}

void Session_data::to_download(const Packet& pack) {
    download.push_back(pack);
}


void Session_data::checking_for_signatures(const Packet& pack, const char *expr) {
    const char *payload = (char *)pack.get_pload();
    if ( strstr(payload, expr) != NULL) {
        string s(expr);
        session_solution = s;
        solution = true;
    }
}

void Session_data::print_payload(int length, const u_char *payload) const { // вывод полезной нагрузки пакетов
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

void Session_data::clean_session_data() {
    upload.clear();
    download.clear();
}


Signature_analysis::Signature_analysis() {
}

void Signature_analysis::print_sessions_list() {
    //EL в 11 стандарте есть auto
    map<Session, Session_data>::iterator iter;
    iter = sessions_list.begin();
    while(iter != sessions_list.end()) {
        Session session = iter->first;
        Session_data s_date = iter->second;
        if (s_date.has_solution()) {
            session.print_session();
            cout << s_date.get_session_solution() << endl << endl;
        }
        iter++;
    }
}

void Signature_analysis::add_packet(const Packet& pack) {
    //EL minor хорошо бы утсранить 2 find'а
    Session session(pack);
    map<Session, Session_data>::iterator iter;
    iter = sessions_list.find(session);
    if (iter != sessions_list.end()) {
        if (sessions_list[session].has_solution()) {
            return;
        }
        sessions_list[session].to_upload(pack);
    }
    else {
        session.session_reverse(); // если уже есть -> добавить, если нет -> создать
        iter = sessions_list.find(session);
        if (iter != sessions_list.end()) {
            if (sessions_list[session].has_solution()) {
                return;
            }
            sessions_list[session].to_download(pack);
        }
        else {
            session.session_reverse();
            sessions_list[session].to_upload(pack);
        }
    }

    char expr[] = "HTTP/1.1"; // список сигнатур..
    sessions_list[session].checking_for_signatures(pack, expr);
    if (sessions_list[session].has_solution()) {
        session.print_session();
        cout << sessions_list[session].get_session_solution() << endl << endl;
        sessions_list[session].clean_session_data(); // я не стал полностью удалять элемент map, потому что тогда в случае прихода паакета из это же сессии обект создастся вновь и будет приниматься решение
    }
}



