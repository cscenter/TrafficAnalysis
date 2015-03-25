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
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>

#include "class_sniff.h"



class PackData {
public:
    struct in_addr src;
    vector<u_char*> UpLoad;
    vector<u_char*> DownLoad;

    PackData();

    void FormPackDate(Session session, SplitPacket pack);
};

class SignatureAnalisator {

    map<Session, PackData> Map;

public:

    SignatureAnalisator();

    map<Session, PackData> GetMap() {
        return Map;
    }

    void PrintMap();

    void FormMap(vector<SplitPacket> Packets);

    Session GetSession(SplitPacket pack);
};
