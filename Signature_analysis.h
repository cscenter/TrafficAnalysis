#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <fstream>
#include <map>
#include <regex>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "Pack_headers_struct.h"
#include "Packet.h"
#include "Session.h"
#include "Configuration.h"



struct Traffic {
    std::string type;
    std::regex signature;
    int priority;
    int num_pack;

    Traffic(std::string sign, std::string t, int p, int n) : signature(sign), type(t), priority(p), num_pack(n) {
    }
};


class Session_data {
private:
    bool solution;
    int solution_priority;
    int solution_num_pack;
    std::string session_solution;
public:
    std::vector<const Packet*> upload;
    std::vector<const Packet*> download;

    Session_data();

    bool has_solution() const { return solution; }

    std::string get_session_solution() const { return session_solution; }

    void set_session_solution(const std::string& solution, int priority, int num_pack);

    void to_upload(const Packet* pack);

    void to_download(const Packet* pack);

    std::vector<const Packet*>& get_upload() { return upload; }

    std::vector<const Packet*>& get_download() { return download; }

    void print_payload(int length, const u_char *payload) const;

    void clean_session_data();

};


class Signature_analysis {

    std::string mode;

    std::string xml_file_name;

    std::map<Session, Session_data> sessions_list;

    std::vector<Traffic> sign_type_list;

    void checking_for_signatures(const Packet* pack, Session_data& ) const;

    std::ofstream out;

public:

    Signature_analysis();

    //~Signature_analysis();

    std::map<Session, Session_data>& get_map() { return sessions_list; } //&?

    void print_sessions_list();

    void add_packet(const Packet* pack);

};

#endif
