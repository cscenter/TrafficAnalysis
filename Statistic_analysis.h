#ifndef STATISTIC_ANALYSIS_H
#define STATISTIC_ANALYSIS_H
#include <pcap.h>
#include "Packet.h"
#include <map>
#include "Session.h"
#include <vector>
#include "Statistic_data.h"

//EL заглавные буквы NONE и префикс TYPE_NONE
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
    std::vector<double> type_percent;
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
        type_percent.resize(4);
        up_init_sec = 0;
        time_to_live = 10;
        up_prev_sec = -1;
        down_init_sec = 0;
        down_prev_sec = -1;
        state_period = 3;
        state_limit = 128;
    }
};



class Statistic_analysis {
    Statistic_data stat_data;
    int processed_sessions_counter;
    int process_interval;
    int last_process_time;
    int host_ip;
    std::map<Session, Packages> pack_time;
    void write_session_to_file(const Session& first, const Packages& second);
    void process_dead_sessions(int current_time);
    void process_all_sessions();
    void dead_session_inform(const Session& ses) const;
    bool fill_state(Packages& p);
    bool fill_period_type(Packages& p);
    void fill_if_not_equal(Packages& p); //если размеры uplink и downlink не равны, дозаполним меньший нулями
    int make_solution(const Packages& p);
    void print_solution(int solution);
public:
    Statistic_analysis();
    Statistic_analysis(int process_interval, int period);

    ~Statistic_analysis();

    void add_packet(const Packet& p);
};


#endif
