#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <arpa/inet.h>
#include <string>

#include "Statistic_analysis.h"

using namespace std;

Statistic_analysis::Statistic_analysis() {
    processed_sessions_counter = 0;
    process_interval = 10;
}


void Statistic_analysis::add_packet(const Split_packet& p) {   //FILL MAP
        time_t current_time = time(NULL); // current time in seconds
        if (current_time - last_process_time > process_interval) {
            process_dead_sessions();
            last_process_time = current_time;
        }
        Session temp_ses, temp_ses2;
        temp_ses.ip_src = p.ip.ip_src;
        temp_ses.ip_dst = p.ip.ip_dst;
        temp_ses.protocol = p.ip.ip_p;
        temp_ses2.ip_src = p.ip.ip_dst;
        temp_ses2.ip_dst = p.ip.ip_src;
        temp_ses2.protocol = p.ip.ip_p;
        switch(p.ip.ip_p) {
            case IPPROTO_TCP:
                temp_ses.port_src = p.tcp.th_sport;
                temp_ses.port_dst = p.tcp.th_dport;
                temp_ses2.port_src = p.tcp.th_dport;
                temp_ses2.port_dst = p.tcp.th_sport;
                break;
            case IPPROTO_UDP:
                temp_ses.port_src = p.udp.s_port;
                temp_ses.port_dst = p.udp.d_port;
                temp_ses2.port_src = p.udp.d_port;
                temp_ses2.port_dst = p.udp.s_port;
                break;
        }
        map<Session, Packages>::iterator it = Pack_time.find(temp_ses);
        map<Session, Packages>::iterator it2 = Pack_time.find(temp_ses2);


        if (it != Pack_time.end()) {
            if (p.header.ts.tv_sec > it->second.up_prev_sec + 1 && it->second.up_prev_sec != -1 ) {
                int j;

                for (j = 0; j < p.header.ts.tv_sec - it->second.up_prev_sec  - 1; j++) {
                    it->second.uplink.push_back(0);
                }
                // it->second.up_prev_sec = p.header.ts.tv_sec;
            }
            if (it->second.up_prev_sec  == (int)(p.header.ts.tv_sec)) it->second.uplink[it->second.uplink.size() - 1]++;
            else {
                it->second.up_prev_sec = p.header.ts.tv_sec;
                it->second.uplink.push_back(1);
            }
        }
        else if (it2 != Pack_time.end()) {
            if (it2->second.up_init_sec == 0) it2->second.up_init_sec = p.header.ts.tv_sec;
            if (p.header.ts.tv_sec > it2->second.down_prev_sec + 1 && it2->second.down_prev_sec != -1 ) {
                int j;
                for (j = 0; j < p.header.ts.tv_sec - it2->second.down_prev_sec  - 1; j++) {
                   it2->second.downlink.push_back(0);
                }
                //it2->second.down_prev_sec = p.header.ts.tv_sec;
            }
            if (it2->second.down_prev_sec == (int)(p.header.ts.tv_sec)) {
                it2->second.downlink[it2->second.downlink.size() - 1]++;
            }
            else {
                 it2->second.down_prev_sec = p.header.ts.tv_sec;
                 it2->second.downlink.push_back(1);
            }
        }
        else {
            Pack_time[temp_ses].ip = p.ip;
            Pack_time[temp_ses].uplink.push_back(1);
            Pack_time[temp_ses].up_init_sec = p.header.ts.tv_sec;
            Pack_time[temp_ses].up_prev_sec = p.header.ts.tv_sec;
        }

}

void Statistic_analysis::print_map() {
    cout << "MAP SIZE " << Pack_time.size();
    map<Session, Packages>::iterator it;
    for(it = Pack_time.begin(); it != Pack_time.end(); it++) {
        cout << "src_ip " << inet_ntoa(it->first.ip_src) << endl;
        cout << "dst_ip " << inet_ntoa(it->first.ip_dst) << endl;
        cout << "src_port " << ntohs(it->first.port_src) << endl;
        cout << "dst_port " << ntohs(it->first.port_dst) << endl;
        cout << it->second.uplink.size() << endl;
        cout << it->second.downlink.size() << endl;
    }
}

void Statistic_analysis::dead_session_inform(Session ses) {
    cout << "Session from ip " << inet_ntoa(ses.ip_src);
    cout << " to " << inet_ntoa(ses.ip_dst) << endl;
    cout << "port src " << ntohs(ses.port_src);
    cout << " port dst " <<  ntohs(ses.port_dst) << endl;
    cout << "protocol " << ses.protocol << endl;
    time_t current_time = time(NULL); // current time in seconds
    cout << "time of last packet "<< ses.time_of_last_packet << " now is " << current_time << endl;
    cout << "IS DEAD" << endl;
}

void Statistic_analysis::write_session_to_file(map<Session, Packages>::iterator it) {
    string uplink_file_name = "ses_" + to_string(processed_sessions_counter) + "_uplink.txt";
    ofstream out_up(uplink_file_name);
    cout << "session number " << processed_sessions_counter << " ip_src " << inet_ntoa(it->first.ip_src) << endl;
    for (int i = 0; i < it->second.uplink.size(); i++) {
        out_up << i << " " << it->second.uplink[i] << endl;
    }
    out_up.close();
    string downlink_file_name = "ses_" + to_string(processed_sessions_counter) + "_downlink.txt";
    ofstream out_down(downlink_file_name);
    for (int i = 0; i < it->second.downlink.size(); i++) {
        out_down << i << " " << it->second.downlink[i] << endl;
    }
    out_down.close();

}

void Statistic_analysis::process_dead_sessions() {
    cout << "Starting_to_process..." << endl;
    cout << "Size of map before " << Pack_time.size() << endl;
    map<Session, Packages>::iterator it;
    for(it = Pack_time.begin(); it != Pack_time.end(); it++) {
            if (!it->first.is_alive()) {
                dead_session_inform(it->first);
                write_session_to_file(it);
                Pack_time.erase(it);
                processed_sessions_counter++;
            }
    }
    cout << "Size of map after " << Pack_time.size() << endl;
}

void Statistic_analysis::write_map() {
    cout << "size = " << Pack_time.size() << endl;
    map<Session, Packages>::iterator it;
    int counter = 0;
    for(it = Pack_time.begin(); it != Pack_time.end(); it++) {
        string uplink_file_name = "ses_" + to_string(counter) + "_uplink.txt";
        ofstream out_up(uplink_file_name);
        cout << "session number " << counter << " ip_src " << inet_ntoa(it->first.ip_src) << endl;
        for (int i = 0; i < it->second.uplink.size(); i++) {
                out_up << i << " " << it->second.uplink[i] << endl;
        }
        out_up.close();
        string downlink_file_name = "ses_" + to_string(counter) + "_downlink.txt";
        ofstream out_down(downlink_file_name);
        for (int i = 0; i < it->second.downlink.size(); i++) {
                out_down << i << " " << it->second.downlink[i] << endl;
        }
        out_down.close();
        counter++;
    }
}


