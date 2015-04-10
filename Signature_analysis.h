#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <map>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "Pack_headers_struct.h"
#include "Parse_packet.h"
#include "Session.h"


class Pack_data {

    in_addr src;

    std::vector<u_char*> upload;

    std::vector<u_char*> download;

public:

    Pack_data();

    void to_upload(Split_packet pack);

    void to_download(Split_packet pack);

    int check_date(const char *expr);

    void print_payload(int length, const u_char *payload);

};


class Signature_analysis {

    std::map<Session, Pack_data> Map;

    Session get_session(Split_packet pack);

public:

    Signature_analysis();

    std::map<Session, Pack_data> get_map() {
        return Map;
    }

    void print_map();

    void form_map(std::vector<Split_packet> Packets);

    void add_packet(const Split_packet& pack);

};

#endif
