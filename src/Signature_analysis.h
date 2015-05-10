#ifndef SIGNATURE_ANALISATOR_H
#define SIGNATURE_ANALISATOR_H

#include <fstream>
//#include <map>
#include <regex>
#include <vector>
#include "Packet.h"
#include "Session_info.h"


struct Traffic {
    std::string type;
    std::regex signature;
    int priority;
    int num_pack;

    Traffic(const std::string& sign, const std::string& t, int p, int n) : signature(sign), type(t), priority(p), num_pack(n) {}
};

class Session_data {
private:
    bool solution = false;
    int solution_priority = -1;
    int solution_num_pack = 0;
    std::string session_solution = "";
    int last_packet_time = 0;
    std::vector<const Packet*> upload;
    std::vector<const Packet*> download;

    void set_last_packet_time(const int& new_time_val);
public:

    bool has_solution() const { return solution; }
    std::string get_session_solution() const { return session_solution; }
    void set_session_solution(const std::string& solution, int priority, int num_pack);

    void to_upload(const Packet* pack);
    void to_download(const Packet* pack);

    std::vector<const Packet*>& get_upload() { return upload; } // почему не получается сделать метод константным?
    std::vector<const Packet*>& get_download() { return download; }

    int get_last_packet_time() const { return last_packet_time; }

};


class Signature_analysis {
private:
    std::map<Session, Session_data> sessions_list;
    std::vector<Traffic> sign_type_list;
    std::ofstream out;
    int last_activity_time = 0;
    int sessions_lifetime;
    int time_to_check;

    void checking_for_signatures(const Packet* pack, Session_data& ) const;
    void start_sessions_kill();
    bool is_alive(const Session_data& s_data) const;
    void free_session_packets(Session_data& s_data);
public:

    Signature_analysis();
    ~Signature_analysis();

    void print_sessions_list();
    void add_packet(const Packet* pack);
    //std::map<Session, Session_data>& get_map() { return sessions_list; } //&?
};

#endif
