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
#include <time.h>


class PackData {
public:
    struct in_addr src;
    vector<int, char*> UpLoad;
    vector<int, char*> DownLoad;

    PackData();
}

class SignatureAnalisator {
public:
    map<Session, PackData> Map;

    SignatureAnalisator();

    void FormMap(vector <SplitPacket>);

    Session GetSession(SplitPacket);

}
