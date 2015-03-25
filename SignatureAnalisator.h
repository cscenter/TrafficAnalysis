#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>

//#include <ctype.h>
#include <errno.h>
//#include <sys/types.h>
//#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>



class PackData {
public:
    struct in_addr src;
    vector<string> UpLoad;
    vector<string> DownLoad;

    PackData();

    void FormPackDate(Session session, SplitPacket pack);
}

class SignatureAnalisator {

    map<Session, PackData> Map;

public:

    SignatureAnalisator();

    map<Session, PackData> GetMap() {
        return Map;
    }

    void FormMap(vector <SplitPacket> Packets);

    Session GetSession(SplitPacket pack);
}
