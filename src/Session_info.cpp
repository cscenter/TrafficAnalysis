#include "Session_info.h"
#include <iostream>


bool Solution::has_sign_solution() {
    if (sign_solution == "") {
        return false;
    }
    return true;
}

bool Solution::has_stat_solution() {
    if (stat_solution == "") {
        return false;
    }
    return true;
}

void Solution::print_solution() const {
    std::cout << "Statistical analysis: " << stat_solution << std::endl;
    std::cout << "Signature analysis:   " << sign_solution << std::endl;
}

Session_info* Session_info::s_info = 0;

void Session_info::display_solution(const Session& session, const Solution& solution) const {
 	if ( !(solution.sign_solution == "none" && solution.stat_solution == "none") ) {
    	session.print_session();
    	solution.print_solution();
	}
}

void Session_info::set_sign_solution(const Session& session, const std::string& solution) {
    solution_list[session].sign_solution = solution;
    if (solution_list[session].has_stat_solution()) {
        display_solution(session, solution_list[session]);
    }
}

void Session_info::set_stat_solution(const Session& session, const std::string& solution) {
    solution_list[session].stat_solution = solution;
    if (solution_list[session].has_sign_solution()) {
        display_solution(session, solution_list[session]);
    }
}

