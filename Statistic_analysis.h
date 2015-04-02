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
    std::map<Session, Packages> Pack_time;
public:
    //const allPackets&
    Statistic_analysis(All_packets p);
    void print_map();
    void write_map();
};
