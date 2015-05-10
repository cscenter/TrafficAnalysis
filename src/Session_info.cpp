#include "Session_info.h"


void Solution::has_sign_solution() {
    if (sign_solution == "") {
        return false;
    }
    return true;
}

void Solution::has_stat_solution() {
    if (stat_solution == "") {
        return false;
    }
    return true;
}

void Solution::print_solution() {
    cout << "Statistical analysis: " << stat_solution << endl;
    cout << "Signature analysis:   " << sign_solution << endl;
}

void Session_info::display_solution(const Session& session, const Solution& solution) const {
    session.print_session();
    solution.print_solution();
}

void Session_info::set_sign_solution(const Session& session, const std::string& solution) {
    solution_list[session].sign_solution = solution;
    if solution_list[session].has_stat_solution()) {
        display_solution(session, solution_list[session]);
    }
}

void Session_info::set_stat_solution(const Session& session, const std::string& solution) {
    solution_list[session].stat_solution = solution;
    if (solution_list[session].has_sign_solution()) {
        display_solution(session, solution_list[session]);
    }
}

