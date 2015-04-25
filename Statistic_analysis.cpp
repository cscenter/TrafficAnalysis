#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "Statistic_analysis.h"

using namespace std;


Statistic_analysis::Statistic_analysis() {
    processed_sessions_counter = 0;
    process_interval = 10;
    last_process_time = 0;
    host_ip = 1684383936;
    mkdir("result", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

bool Statistic_analysis::fill_state(Packages& p) {
	int true_counter = 0, false_counter = 0, up_null_counter = 0, down_null_counter = 0, sum = 0;
	for (int i = 0; i < p.uplink.size(); i++) {
        sum += p.uplink[i];
		if ((i + 1) % p.state_period == 0 || i == p.uplink.size() - 1) {
		    //if (true_counter > false_counter) {
		    if (sum > p.state_limit) {  
			    p.up_state.push_back(true);
		    }
		    else {
			    p.up_state.push_back(false);
		    }
		    sum = 0;
	    }
    }
	
	sum = 0;
	for (int i = 0; i < p.downlink.size(); i++) {
        sum += p.downlink[i];
		if ((i + 1) % p.state_period == 0 || i == p.downlink.size() - 1) {
			if (sum > p.state_limit) {
				p.down_state.push_back(true);
			}
			else {
				p.down_state.push_back(false);
			}
			sum = 0;
		}
		
		
	}
	
	if (down_null_counter == p.downlink.size() && up_null_counter == p.uplink.size()) return false;
	return true;
}

bool Statistic_analysis::fill_period_type(Packages& p) {
    int null_counter = 0;
    traffic_type tr_t;
    for (int i = 0; i < p.up_state.size(); i++) {
        if (p.up_state[i] && p.down_state[i]) {
            tr_t = interactive;
        }
        else if (!p.up_state[i] && p.down_state[i]) {
            tr_t = download;
        }
        else if (p.up_state[i] && !p.down_state[i]) {
            tr_t = upload;
        }
        else {
            tr_t = none;
            null_counter++;
        }
        p.period_type.push_back(tr_t);
        p.type_percent[(int)tr_t]++;
    }
    for (int i = 0; i < p.type_percent.size(); i++) {
        p.type_percent[i] /= p.up_state.size();
    }
    if (null_counter == p.up_state.size()) return false;
    return true;
}


 			

void Statistic_analysis::fill_if_not_equal(Packages& p) {
	/*if (p.downlink.size() > p.uplink.size()) {
	    for (int i = 0; i < p.downlink.size() - p.uplink.size(); i++) {
	        p.uplink.push_back(0);
	        cout << " up " << endl;
	    }
	} else {
	    for (int i = 0; i < p.uplink.size() - p.downlink.size() + 1; i++) {
	        p.downlink.push_back(0);
	        cout << " down " << endl;
	    }
    } ??????? */
    
    
    if (p.downlink.size() > p.uplink.size()) p.uplink.resize(p.downlink.size());
    else if (p.downlink.size() < p.uplink.size()) p.downlink.resize(p.uplink.size());
}


void Statistic_analysis::print_solution(int solution) {
    cout << "ses " << processed_sessions_counter << " ";
    switch(solution) {
        case 0: cout << "download" << endl; break;
        case 1: cout << "browsing" << endl; break;
    }
}

int Statistic_analysis::make_solution(const Packages& p) {
    int solution = stat_data.get_nearest(p.type_percent);
    print_solution(solution);
    return solution;
}



void Statistic_analysis::process_dead_sessions(int current_time) {
    auto it = pack_time.begin();
    while (it != pack_time.end()) {
        if (!it->second.is_alive(current_time)) {
            //dead_session_inform(it->first);
            fill_if_not_equal(it->second);
            if (fill_state(it->second) && fill_period_type(it->second)
                && !(it->second.downlink.size() < 3 ||it-> second.uplink.size() < 3)) {
                make_solution(it->second);
                write_session_to_file(it->first, it->second);
            }
            pack_time.erase(it++);
            processed_sessions_counter++;
        }
        else it++;
    }
    //cout << "Size of map after " << pack_time.size() << endl;
}


void Statistic_analysis::process_all_sessions() {
    //cout << "Starting_to_process..." << endl;
    //cout << "Size of map before " << pack_time.size() << endl;
    map<Session, Packages>::iterator it = pack_time.begin();
    while (it != pack_time.end()) {
         fill_if_not_equal(it->second);
         if ( fill_state(it->second) && fill_period_type(it->second)
            && !(it->second.downlink.size() < 3 ||it-> second.uplink.size() < 3) ) {
            make_solution(it->second);
            write_session_to_file(it->first, it->second);
         }
        pack_time.erase(it++);
        processed_sessions_counter++;
            
    }
    //cout << "Size of map after " << Pack_time.size() << endl;
}


bool Packages::is_alive(int current_time) {
    return current_time - last_packet_time() < time_to_live;
}

int Packages::last_packet_time() {
    return (up_prev_sec > down_prev_sec) ? up_prev_sec : down_prev_sec;
}

Statistic_analysis::~Statistic_analysis() {
    cout << "destructor " << endl;
    process_all_sessions();
}

void Statistic_analysis::add_packet(const Packet& p) {   //FILL MAP
    int p_time = p.get_header().ts.tv_sec;
    if (p_time - last_process_time > process_interval) {
        process_dead_sessions(p_time);
        last_process_time = p_time;
    }

    int p_size = p.get_size_payload();
    Session temp_ses(p);
    bool is_reversed = false;
    if (temp_ses.ip_src.s_addr != host_ip) {
        is_reversed = true;
        temp_ses.session_reverse();
    }
    map<Session, Packages>::iterator it = pack_time.find(temp_ses);
    if (!is_reversed && it != pack_time.end()) {
        //EL из за длинных названий тяжело читать
        int * prev_sec = &(it->second.up_prev_sec);
        if (p_time > *prev_sec + 1 && *prev_sec != -1 ) {
            int j;
            for (j = 0; j < p_time - *prev_sec - 1; j++) {
                it->second.uplink.push_back(0);
            }
        *prev_sec = p_time;
        }
        if (*prev_sec  == (int)(p_time)) {
            it->second.uplink[it->second.uplink.size() - 1] += p_size;
        }
        else {
            *prev_sec = p_time;
            it->second.uplink.push_back(p_size);
        }
    }
    else if (is_reversed && it != pack_time.end()) {
        if (it->second.up_init_sec == 0) it->second.up_init_sec = p_time;
        if (p_time > it->second.down_prev_sec + 1 && it->second.down_prev_sec != -1 ) {
            int j;
            for (j = 0; j < p_time - it->second.down_prev_sec  - 1; j++) {
               it->second.downlink.push_back(0);
            }
            //it2->second.down_prev_sec = p_time;
        }
        if (it->second.down_prev_sec == (int)(p_time)) {
            it->second.downlink[it->second.downlink.size() - 1] += p_size;
        }
        else {
             it->second.down_prev_sec = p_time;
             it->second.downlink.push_back(p_size);
        }
    }
    else {
      // ?  pack_time[temp_ses].ip = p_ip;
        if (!is_reversed) {    //надо сделать const int our_addr как поле класса
            pack_time[temp_ses].uplink.push_back(p_size);
            pack_time[temp_ses].up_init_sec = p_time;
            pack_time[temp_ses].up_prev_sec = p_time;
        }
        else {
            pack_time[temp_ses].downlink.push_back(p_size);
            pack_time[temp_ses].down_init_sec = p_time;
            pack_time[temp_ses].down_prev_sec = p_time;
        }
    }


}


void Statistic_analysis::dead_session_inform(const Session & ses) const {
    cout << "Session from ip " << inet_ntoa(ses.ip_src);
    cout << " to " << inet_ntoa(ses.ip_dst);
    cout << "  IS DEAD" << endl << endl;
    
}

void Statistic_analysis::write_session_to_file(const Session& first, const Packages& second) {
    string file_name = "result/ses" + to_string(processed_sessions_counter) + "_uplink.txt";
    ofstream out_up(file_name);
    /*out_up << inet_ntoa(first.ip_dst) << endl;
    out_up << " to " << inet_ntoa(first.ip_dst) << endl;
    out_up << first.port_src <<  " " << first.port_dst << endl;
    switch(first.protocol) {
        case IPPROTO_TCP:
            out_up << "TCP" << endl;
            break;
        case IPPROTO_UDP:
            out_up << "UDP" << endl;
            break;
    } */

    for (int i = 0; i < second.uplink.size(); i++) {
        out_up << i << " " << second.uplink[i] << endl;
    }
    out_up.close();
    file_name = "result/ses" + to_string(processed_sessions_counter) + "_downlink.txt";
    ofstream out_down(file_name);
    for (int i = 0; i < second.downlink.size(); i++) {
        out_down << i << " " <<  second.downlink[i] << endl;
    }
    out_down.close();
    int period = second.state_period;
    file_name = "result/ses" + to_string(processed_sessions_counter) + "_up_state.txt";
    ofstream out_up_state(file_name);
    out_up_state << 0 << " " << second.up_state[0] << endl;
    
    for (int i = 0; i < second.up_state.size(); i++) {
        out_up_state << (i + 1) * period - 1 << " " << second.up_state[i] << endl;
    }
    out_up_state.close();

    file_name = "result/ses" + to_string(processed_sessions_counter) + "_down_state.txt";
    ofstream out_down_state(file_name);
    out_down_state << 0 << " " << second.down_state[0] << endl;
    for (int i = 0; i < second.down_state.size(); i++) {
        out_down_state << (i + 1) * period - 1 << " " << second.down_state[i] << endl;
    }
    out_down_state.close();
    
    file_name = "result/ses" + to_string(processed_sessions_counter) + "_period_types.txt";
    ofstream out_period_types(file_name);

    out_period_types << 0 << " " << second.period_type[0] << endl;
    for (int i = 0; i < second.period_type.size(); i++) {
        out_period_types << (i + 1) * period - 1 << " " << second.period_type[i] << endl;
        out_period_types << (i + 1) * period - 1 << " " << second.period_type[i] << endl;
    }
    out_period_types.close();

}
