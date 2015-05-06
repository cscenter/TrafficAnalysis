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

void Session_data::to_upload(const Packet* pack) {
    upload.push_back(pack);
}

void Session_data::to_download(const Packet* pack) {
    download.push_back(pack);
}

void Session_data::set_session_solution(const string& solut, int priority, int num_pack) {
    if (solution_priority < priority) {
        session_solution = solut;
        solution_priority = priority;
        solution_num_pack = num_pack;
    }
    if (solution_priority == priority && session_solution == solut) {
        if (--solution_num_pack == 0) {
            solution = true;
        }
    }
}

Signature_analysis::Signature_analysis() {
    Config* main_config = Config::get_config(); // вызывается конструктор наследного класса, вызывается конструктор базового
    main_config->load_xml_file("xml/configurations.xml"); // подгружается xml файл
    main_config->get_tag("sign_config");

    string f_name;
    main_config->get_attribute_str("file_name", f_name);
    main_config->load_xml_file(f_name);

    while (main_config->next_tag()) {
        string sign, type;
        int priority, num_pack;
        //main_config->get_next_signature(sig, type, &priority, &num_pack);
        bool status = main_config->get_attribute_str("sign", sign);
        main_config->get_attribute_str("type", type);
        main_config->get_attribute_int("priority", &priority);
        main_config->get_attribute_int("num_pack", &num_pack);
        if (status) {
            Traffic traffic(sign, type, priority, num_pack);
            sign_type_list.push_back(traffic);
        }
    }
}

void Signature_analysis::print_sessions_list() {
    out.open("session_without_solution_pload.txt", ios::out);
    map<Session, Session_data>::iterator iter;
    iter = sessions_list.begin();
    while(iter != sessions_list.end()) {
        Session session = iter->first;
        Session_data s_date = iter->second;
        if (!s_date.has_solution()) {
            //session.print_session();
            vector<const Packet*> upload = s_date.get_upload();
            vector<const Packet*> download = s_date.get_download();

            for ( int i = 0; i < download.size(); i++) {
                out << download[i]->get_pload() << endl;
            }
            out << endl << "----------------------------------" << endl;
            for ( int i = 0; i < upload.size(); i++) {
                out << upload[i]->get_pload() << endl;
            }
            out << endl << "/********************************/" << endl;
        }
        iter++;
    }
    out.close();
}


void Signature_analysis::add_packet(const Packet* p) {
    Packet *pack = new Packet(*p);
    Session session(*pack);
    map<Session, Session_data>::iterator iter;
    iter = sessions_list.find(session);
    if (iter != sessions_list.end()) {
        if (sessions_list[session].has_solution()) {
            delete pack;
            return;
        }
        sessions_list[session].to_upload(pack);
    }
    else {
        session.session_reverse(); // если уже есть -> добавить, если нет -> создать
        iter = sessions_list.find(session);
        if (iter != sessions_list.end()) {
            if (sessions_list[session].has_solution()) {
                delete pack;
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
        out.open("session_with_solution_pload.txt", ios::app);
        out << pack->get_pload() << endl << "/*****************************/" << endl;
        out.close();
    }
}

void Signature_analysis::checking_for_signatures(const Packet* pack, Session_data& session) const {
    string payload((char *)pack->get_pload());
    for ( int i = 0; i < sign_type_list.size(); i++ ) {
        if (regex_search(payload, sign_type_list[i].signature)) {
           session.set_session_solution(sign_type_list[i].type, sign_type_list[i].priority, sign_type_list[i].num_pack);
        }
    }
}
/*
Signature_analysis::~Signature_analysis() {
    map<Session, Session_data>::iterator iter;
    iter = sessions_list.begin();
     while(iter != sessions_list.end()) {
        Session session = iter->first;
        Session_data s_date = iter->second;
        vector<const Packet*> upload = s_date.get_upload();
        vector<const Packet*> download = s_date.get_download();
        for ( int i = 0; i < download.size(); i++) {
            delete download[i];
        }
        for ( int i = 0; i < upload.size(); i++) {
            delete upload[i];
        }
    }
    iter++;
}*/
/*void Session_data::print_payload(int length, const u_char *payload) const { // вывод полезной нагрузки пакетов
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
}*/

