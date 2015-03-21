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

#include "class_sniff.h"

struct Packages
{
    struct sniff_ip *ip;
    vector<int> uplink;
    vector<int> downlink;
};

class StatisticAnalysis
{
    map<Session, Packages> PackagesTime;
public:
    StatisticAnalysis(allPackets p);
};
