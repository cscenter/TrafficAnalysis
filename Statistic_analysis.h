#ifndef STATISTIC_ANALYSIS_H
#define STATISTIC_ANALYSIS_H
#include <pcap.h>
#include "Parse_packet.h"
#include <map>
#include "Session.h"
#include <vector>

//EL: check style
struct Packages {
    struct sniff_ip ip;
    std::vector<int> uplink;
    std::vector<int> downlink;
    int up_init_sec;
    int up_prev_sec;
    int down_init_sec;
    int time_to_live;
    int down_prev_sec;
    bool is_alive(int);
    int last_packet_time();
    Packages() {
        up_init_sec = 0;
        time_to_live = 10;
        up_prev_sec = -1;
        down_init_sec = 0;
        down_prev_sec = -1;
    }
};



class Statistic_analysis {
    int processed_sessions_counter;
    int process_interval;
    int last_process_time;
    //EL поля с маленькой буквы
    std::map<Session, Packages> Pack_time;
public:
    Statistic_analysis();
    ~Statistic_analysis();
    Statistic_analysis(int process_interval);
    //EL параметры этого метода не должны зависеть 
    //от метода хранения объектов в классе
    void write_session_to_file(std::map<Session, Packages>::iterator it);
    void process_dead_sessions(int current_time);
    void add_packet(const Split_packet& p);
    void print_map();
    void process_all_sessions();
    //EL const&
    void dead_session_inform(Session ses);
    void write_map();
};


#endif
