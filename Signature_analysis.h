#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <map>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "Pack_headers_struct.h"
#include "Packet.h"
#include "Session.h"


//EL Может Session_data?
class Pack_data {

    in_addr src;

    std::vector<Packet> upload;

    std::vector<Packet> download;

public:

    Pack_data();

    void to_upload(const Packet& pack);

    void to_download(const Packet& pack);

    int checking_for_signatures(const char *expr);

    void print_payload(int length, const u_char *payload);

};


class Signature_analysis {

    std::map<Session, Pack_data> sessions_list;

public:

    Signature_analysis();
    //EL лишние копирования
    std::map<Session, Pack_data>& get_map() { //???
        return sessions_list;
    }

    void print_sessions_list();

    //EL зачем на стеке копия?
    //void form_map(std::vector<Split_packet> Packets);

    void add_packet(const Packet& pack);

};

#endif
