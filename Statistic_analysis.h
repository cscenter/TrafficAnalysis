#include "Net_sniffer.h"

//EL: check style
struct Packages {
    struct sniff_ip ip;
    std::vector<int> uplink;
    std::vector<int> downlink;
    int up_init_sec;
    int up_prev_sec;
    int down_init_sec;
    int down_prev_sec;
    Packages() {
        up_init_sec = 0;
        up_prev_sec = -1;
        down_init_sec = 0;
        down_prev_sec = -1;
    }
};

class Statistic_analysis {
    int processed_sessions_counter;
    int process_interval;
    int last_process_time;
    std::map<Session, Packages> Pack_time;
public:
    Statistic_analysis();
    Statistic_analysis(int process_interval);
    void write_session_to_file(map<Session, Packages>::iterator it);
    void process_dead_sessions();
    void add_packet(const Split_packet& p);
    void print_map();
    void dead_session_inform(Session ses);
    void write_map();
};
