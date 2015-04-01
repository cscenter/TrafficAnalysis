#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include <time.h>

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

class StatisticAnalysis {
    std::map<Session, Packages> PackagesTime;
public:
    //const allPackets&
    StatisticAnalysis(allPackets p);
    void print_map();
    void write_map();
};
