#ifndef SESSION_INFO_H
#define SESSION_INFO_H


#include <map>
#include "Session.h"

struct Solution {
    std::string sign_solution;
    std::string stat_solution;

    Solution() : sign_solution(""), stat_solution("") {}

    bool has_sign_solution();

    bool has_stat_solution();

    void print_solution() const;
};

class Session_info {
private:

    static Session_info *s_info;

    std::map<Session, Solution> solution_list;

    Session_info(){};

    void display_solution(const Session& session, const Solution& solution) const;
public:
    static Session_info* get_session_info() {
        if ( s_info == 0 ) {
            s_info = new Session_info();
        }
        return s_info;
    };

    ~Session_info() {
        delete s_info;
    }

    void set_sign_solution(const Session& session, const std::string& solution);
    void set_stat_solution(const Session& session, const std::string& solution);
};

#endif
