#include <iostream>
#include "Session.h"
#include "Signature_analysis.h"


using namespace std;

Session_data::Session_data() {
    solution = false;
    solution_priority = -1;
    solution_num_pack = 0;
    session_solution = "";
}

//EL: inline в cpp файлы не работает
inline void Session_data::to_upload(const Packet& pack) {
    upload.push_back(pack);
}

inline void Session_data::to_download(const Packet& pack) {
    download.push_back(pack);
}

void Session_data::set_session_solution(const string& solut, int priority) {
    if (solution_priority < priority) {
        session_solution = solut;
        solution_priority = priority;
        solution_num_pack = 1;
    }
    if (solution_priority == priority && session_solution == solut) {
        if (++solution_num_pack > 2) {
            solution = true;
        }
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


Signature_analysis::Signature_analysis(Config& config) {
    while (!config.is_ready()) {
        string sig, type;
        int priority;
        bool state = config.get_next_signature(sig, type, &priority);
        if (state) {
            Traffic traffic(sig, type, priority);
            sign_type_list.push_back(traffic);
        }
    }
}

void Signature_analysis::print_sessions_list() {
    ofstream out("session_without_solution_pload.txt");
    //EL в 11 стандарте есть auto
    map<Session, Session_data>::iterator iter;
    iter = sessions_list.begin();
    while(iter != sessions_list.end()) {
        Session session = iter->first;
        Session_data s_date = iter->second;
        if (!s_date.has_solution()) {
            session.print_session();
            out << endl << "/////////////////////////////////////////////////////////" << endl;
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

    checking_for_signatures(pack, sessions_list[session]);
    if (sessions_list[session].has_solution()) {
        session.print_session();
        cout << sessions_list[session].get_session_solution() << endl << endl;
        ofstream out("session_with_solution_pload.txt", ios::app);
        out << pack.get_pload() << endl << "//////////////////////////////////////////////////////////////////////////////" << endl;
        sessions_list[session].clean_session_data();
    }
}

void Signature_analysis::checking_for_signatures(const Packet& pack, Session_data& session) const {
    string payload((char *)pack.get_pload());
    for ( int i = 0; i < sign_type_list.size(); i++ ) {
        if (regex_search(payload, sign_type_list[i].signature)) {
           session.set_session_solution(sign_type_list[i].type, sign_type_list[i].priority);
        }
    }
}



