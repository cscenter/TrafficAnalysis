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
    //EL может надо хранить vector<какой-нибудь пакет>
    std::vector<u_char*> upload;

    std::vector<u_char*> download;

public:

    Pack_data();

    //EL лучше все передавть по const &
    void to_upload(Packet pack);

    void to_download(Packet pack);
    //EL date значит день
    int check_date(const char *expr);

    void print_payload(int length, const u_char *payload);

};


class Signature_analysis {

    //EL поля с маленькой буквы
    std::map<Session, Pack_data> Map;
    //EL может вернуть & или даже const?
    //EL может написать const у метода
    //Session get_session(Split_packet pack);

public:

    Signature_analysis();

    //EL лишние копирования
    std::map<Session, Pack_data> get_map() {
        return Map;
    }

    void print_map();

    //EL зачем на стеке копия?
    //void form_map(std::vector<Split_packet> Packets);

    void add_packet(const Packet& pack);

};

#endif
