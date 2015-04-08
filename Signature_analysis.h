#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H
#include <map>
#include "Net_sniffer.h"


//EL add private
class PackData {
public:
    struct in_addr src;
    std::vector<u_char*> UpLoad;
    std::vector<u_char*> DownLoad;

    PackData();
    //const Session&
    void FormPackDate(Session session, Split_packet pack);

    int CheckDate(char *expr);
};


//EL add private
class Signature_analysis {

    std::map<Session, PackData> Map;

public:

    Signature_analysis();

    std::map<Session, PackData> GetMap() {
        return Map;
    }

    void PrintMap();

    void FormMap(std::vector<Split_packet> Packets);

    Session GetSession(Split_packet pack);
};

#endif
