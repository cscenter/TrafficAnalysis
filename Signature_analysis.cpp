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
    string f_name("xml/configurations.xml");
    static MainConfig c(f_name); // вызывается конструктор наследного класса, вызывается конструктор базового

    Config *main_config = c.get_config(f_name); // инстанцируется класс синглтон
    main_config->load_xml_file(); // подгружается xml файл
    string *args = new string[3];
    bool state = main_config->get_sign_config(args);

    main_config = c.get_config(args[0]);
    main_config->load_xml_file();
    //Signature_configurations config(args[0].c_str());
    while (!main_config->is_ready()) {
        string sig, type;
        int priority, num_pack;
        state = main_config->get_next_signature(sig, type, &priority, &num_pack);
        if (state) {
            Traffic traffic(sig, type, priority, num_pack);
            sign_type_list.push_back(traffic);
        }
    }
    //delete main_config;
    //delete config;
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

void Signature_analysis::add_packet(const Packet* pack) {
    Session session(*pack);
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

