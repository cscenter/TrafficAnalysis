#include <iostream>
#include <arpa/inet.h>
#include "Configuration.h"
#include "Session.h"
#include "Signature_analysis.h"


using namespace std;

void Session_data::to_upload(const Packet* pack) {
    set_last_packet_time(pack->get_header().ts.tv_sec);
    upload.push_back(pack);
}

void Session_data::to_download(const Packet* pack) {
    set_last_packet_time(pack->get_header().ts.tv_sec);
    download.push_back(pack);
}

void Session_data::set_last_packet_time(const int& new_time_val) {
    if (last_packet_time < new_time_val) {
        last_packet_time = new_time_val;
    }
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
    Config* config = Config::get_config(); // инстанцируется синглтон
    config->load_xml_file("xml/configurations.xml"); // подгружается xml файл с основными настройками
    config->get_tag("sign_config");

    string f_name;
    config->get_attribute_str("file_name", f_name);
    config->get_attribute_int("session_lifetime", &sessions_lifetime);
    config->get_attribute_int("time_to_check", &time_to_check);

    config->load_xml_file(f_name); // загрузка файла со списком регулярных выражений
    do {
        string sign, type, host;
        in_addr ip;
        int priority, num_pack;

        config->get_attribute_str("sign", sign);
        config->get_attribute_str("type", type);

        config->get_attribute_str("host_ip", host); // получаем адрес хоста
        inet_aton(host.c_str(), &ip);
        host_ip = ip.s_addr;

        config->get_attribute_int("priority", &priority);
        config->get_attribute_int("num_pack", &num_pack);
        Traffic traffic(sign, type, priority, num_pack);
        sign_type_list.push_back(traffic);
    }
    while (config->next_tag());
}

void Signature_analysis::add_packet(const Packet* pack) {
    if (pack->get_header().ts.tv_sec - last_activity_time >= time_to_check && last_activity_time) { // проверяю сколько прошло времени
        start_sessions_kill();                                                                      // с прошлой подчистки сессий
        last_activity_time = pack->get_header().ts.tv_sec;
    }

    Session session(*pack); // получение сессии (upload), соответствующей пришедшему пакету

    if (session.ip_src.s_addr != host_ip) {
        session.session_reverse();
    }

    auto iter = sessions_list.find(session);
    if (iter != sessions_list.end()) {
        if (sessions_list[session].has_solution()) {
            delete pack;
            return;
        }
        sessions_list[session].to_upload(pack); // сессия существует -> добавить в upload
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
        out.open("session_with_solution_pload.txt", ios::app);
        Session_info* s_inf = Session_info::get_session_info();
        s_inf->set_sign_solution(session, sessions_list[session].get_session_solution());
        //session.print_session();
        //cout << sessions_list[session].get_session_solution() << endl << endl;
        out << pack->get_pload() << endl << "/*********************/" << endl;
        out.close();
    }

}

void Signature_analysis::checking_for_signatures(const Packet* pack, Session_data& session) const {
    string payload((char *)pack->get_pload());
    for (int i = 0; i < sign_type_list.size(); i++) {
        if (regex_search(payload, sign_type_list[i].signature)) { // проверяю есть ли совпадения по регулярным выражениям в содержимом пакета
           session.set_session_solution(sign_type_list[i].type, sign_type_list[i].priority, sign_type_list[i].num_pack);
        }
    }
}

void Signature_analysis::start_sessions_kill() {
    auto iter = sessions_list.begin();
    while (iter != sessions_list.end()) {
        if (!is_alive(iter->second)) {
            Session_info* s_inf = Session_info::get_session_info();
            s_inf->set_sign_solution(iter->first, "none");

            free_session_packets(iter->second);
            sessions_list.erase(iter++);
        }
    }
}


bool Signature_analysis::is_alive(const Session_data& s_data) const {
    if (last_activity_time - s_data.get_last_packet_time() > sessions_lifetime) { //sessions_lifetime
        return false;
    }
    return true;
}

void Signature_analysis::free_session_packets(Session_data& s_data) {
    vector<const Packet*> download = s_data.get_download();
    for (int i = 0; i < download.size(); i++) {
        delete download[i];
    }

    vector<const Packet*> upload = s_data.get_upload();
    for (int i = 0; i < upload.size(); i++) {
        delete upload[i];
    }
}

Signature_analysis::~Signature_analysis() {
    auto iter = sessions_list.begin();
     while(iter != sessions_list.end()) {
        free_session_packets(iter->second);
        iter++;
    }
}

void Signature_analysis::print_sessions_list() {
    ofstream s_out;
    s_out.open("session_without_solution_pload.txt", ios::out);
    auto iter = sessions_list.begin();
    while(iter != sessions_list.end()) {
        Session session = iter->first;
        Session_data s_date = iter->second;
        if (!s_date.has_solution()) {
            vector<const Packet*> upload = s_date.get_upload();
            vector<const Packet*> download = s_date.get_download();

            for ( int i = 0; i < download.size(); i++) {
                s_out << download[i]->get_pload() << endl;
            }
            s_out << endl << "----------------------------------" << endl;
            for ( int i = 0; i < upload.size(); i++) {
                s_out << upload[i]->get_pload() << endl;
            }
            s_out << endl << "/********************************/" << endl;
        }
        iter++;
    }
    out.close();
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

