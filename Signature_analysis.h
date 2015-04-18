#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <map>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "Pack_headers_struct.h"
#include "Packet.h"
#include "Session.h"
#include <string>


class Session_data {

    bool solution;

    std::string session_solution;

    //EL: Packet* не будет лишних копирований 
    //EL: не забудьте потом удалить пакеты в деструкторе
    std::vector<Packet> upload;

    std::vector<Packet> download;

public:

    Session_data();

    inline bool has_solution() const { return solution; }

    inline std::string get_session_solution() const { return session_solution; } //&? inline?

    void to_upload(const Packet& pack);

    void to_download(const Packet& pack);

    void checking_for_signatures(const Packet& pack, const char *expr);

    void print_payload(int length, const u_char *payload) const;

    void clean_session_data();

};


class Signature_analysis {

    std::map<Session, Session_data> sessions_list;

public:

    Signature_analysis();

    inline std::map<Session, Session_data>& get_map() { return sessions_list; } //&?

    void print_sessions_list();

    void add_packet(const Packet& pack);

};

#endif
