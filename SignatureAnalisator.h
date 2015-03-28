//#include <pcap.h>
//#include <stdio.h>
#include <string.h>
//#include <stdlib.h>
//#include <iostream>
//#include <new>

//#include <ctype.h>
//#include <errno.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <map>
#include <vector>
//#include <string>

#include "class_sniff.h"

//EL add private
class PackData {
public:
    struct in_addr src;
    std::vector<u_char*> UpLoad;
    std::vector<u_char*> DownLoad;

    PackData();
    //const Session&
    void FormPackDate(Session session, SplitPacket pack);

    int CheckDate(char *expr);
};


//EL add private
class SignatureAnalisator {

    std::map<Session, PackData> Map;

public:

    SignatureAnalisator();

    std::map<Session, PackData> GetMap() {
        return Map;
    }

    void PrintMap();

    void FormMap(std::vector<SplitPacket> Packets);

    Session GetSession(SplitPacket pack);
};
