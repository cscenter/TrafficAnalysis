#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H
#include <map>
#include "Net_sniffer.h"


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


//EL add private
class Signature_analysis {

    std::map<Session, Pack_data> Map;

public:

    Signature_analysis();

    std::map<Session, Pack_data> get_map() {
        return Map;
    }

    void print_map();

    void form_map(std::vector<Split_packet> Packets);

    void add_packet(Split_packet pack);

    Session get_session(Split_packet pack);
};

#endif
