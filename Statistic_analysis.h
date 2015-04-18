#ifndef STATISTIC_ANALYSIS_H
#define STATISTIC_ANALYSIS_H
#include <pcap.h>
#include "Packet.h"
#include <map>
#include "Session.h"
#include <vector>

enum traffic_type {
    none, upload, download, interactive
};

struct Packages {
    struct sniff_ip ip;
    std::vector<int> uplink;
    std::vector<int> downlink;
    std::vector<bool> up_state;
    std::vector<bool> down_state;
    std::vector<traffic_type> period_type;
    int state_period;
    int state_limit;
    int up_init_sec;
    int up_prev_sec;
    int down_init_sec;
    int time_to_live;
    int down_prev_sec;
    bool is_alive(int);
    int last_packet_time();
    Packages() {
        up_init_sec = 0;
        time_to_live = 10000;
        up_prev_sec = -1;
        down_init_sec = 0;
        down_prev_sec = -1;
        state_period = 3;
        state_limit = 128;
    }
};



class Statistic_analysis {
    int processed_sessions_counter;
    int process_interval;
    int last_process_time;
    int period;
    std::map<Session, Packages> pack_time;
public:
    Statistic_analysis();
    ~Statistic_analysis();
    Statistic_analysis(int process_interval, int period);
    void write_session_to_file(Session first, Packages second);
    void process_dead_sessions(int current_time);
    void add_packet(const Packet& p);
    void print_map();
    void process_all_sessions();
    void dead_session_inform(const Session& ses) const;
    void write_map();
    bool fill_state(Packages& p);
    bool fill_period_type(Packages& p);
    void fill_if_not_equal(Packages& p); //если размеры uplink и downlink не равны, дозаполним меньший нулями 
};


#endif
