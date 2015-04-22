#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <map>
#include <regex>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "Pack_headers_struct.h"
#include "Packet.h"
#include "Session.h"
#include <string>

using namespace std;


class Session_data {

    bool solution;

    string session_solution;

    //EL: Packet* не будет лишних копирований
    //EL: не забудьте потом удалить пакеты в деструкторе
    vector<Packet> upload;

    vector<Packet> download;

public:

    Session_data();

    inline bool has_solution() const { return solution; }

    inline string get_session_solution() const { return session_solution; } //&? inline?

    void to_upload(const Packet& pack);

    void to_download(const Packet& pack);

    void checking_for_signatures(const Packet& pack, regex reg);
    //void checking_for_signatures(const Packet& pack, const char *expr);

    void print_payload(int length, const u_char *payload) const;

    void clean_session_data();

};


class Signature_analysis {

    map<Session, Session_data> sessions_list;

public:

    Signature_analysis();

    inline map<Session, Session_data>& get_map() { return sessions_list; } //&?

    void print_sessions_list();

    void add_packet(const Packet& pack);

};

#endif
