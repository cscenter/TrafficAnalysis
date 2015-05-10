#ifndef SESSION_INFO_H
#define SESSION_INFO_H

#include "Session.h"

struct Solution {
    std::string sign_solution;
    std::string stat_solution;

    Solution() : sign_solution(""), stat_solution("") {}

    bool has_sign_solution();

    bool has_stat_solution();

    void print_solution();
}

class Session_info {
private:
    std::map<Session, Solution> solution_list;

    void display_solution(const Session& session, const Solution& solution) const;
public:

    void set_sign_solution(const Session& session, const std::string& solution);
    void set_stat_solution(const Session& session, const std::string& solution);
}
