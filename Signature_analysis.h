#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H
#include <map>
//#include "Net_sniffer.h"
#include "Session.h"
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "Pack_headers_struct.h"
#include "Parse_packet.h"

//EL add private
class Pack_data {
public:
    struct in_addr src;
    std::vector<u_char*> upload;
    std::vector<u_char*> download;

    Pack_data();

    void form_pack_date(Session session, Split_packet pack);

    int check_date(const char *expr);

    void print_payload(int length, const u_char *payload);
};

class Signature_analysis {
private:
    
    std::map<Session, Pack_data> Map;

public:

    Signature_analysis();

    std::map<Session, Pack_data> get_map() {
        return Map;
    }

    void print_map();

    void form_map(std::vector<Split_packet> Packets);

    void add_packet(const Split_packet& pack);

    Session get_session(Split_packet pack);
};

#endif
