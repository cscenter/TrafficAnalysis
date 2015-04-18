#include <iostream>
#include <fstream>
#include <sys/socket.h>
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
    mkdir("result", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

bool Statistic_analysis::fill_state(Packages& p) {
	int true_counter = 0, false_counter = 0, up_null_counter = 0, down_null_counter = 0;
	for (int i = 0; i < p.uplink.size(); i++) {
        if (p.uplink[i] > p.state_limit) true_counter++;
	    else false_counter++;
        if (p.uplink[i] == 0) up_null_counter++;
		if ((i + 1) % p.state_period == 0 || i == p.uplink.size() - 1) {
		    //if (true_counter > false_counter) {
		    if (true_counter  > 0) {  
			    p.up_state.push_back(true);
		    }
		    else {
			    p.up_state.push_back(false);
		    }
		    true_counter = 0; 
		    false_counter = 0;
	    }
    }
	
	true_counter = 0; 
	false_counter = 0;
	for (int i = 0; i < p.downlink.size(); i++) {
        if (p.downlink[i]  == 0) down_null_counter++;
	    if (p.downlink[i] > p.state_limit) true_counter++;
		else false_counter++;
		if ((i + 1) % p.state_period == 0 || i == p.downlink.size() - 1) {
			if (true_counter > false_counter) {
				p.down_state.push_back(true);
			}
			else {
				p.down_state.push_back(false);
			}
			true_counter = 0; 
			false_counter = 0;
		}
		
		
	}
	
	if (down_null_counter == p.downlink.size() && up_null_counter == p.uplink.size()) return false;
	return true;
}

bool Statistic_analysis::fill_period_type(Packages& p) {
    int null_counter = 0;
    for (int i = 0; i < p.up_state.size(); i++) {
        if (p.up_state[i] && p.down_state[i]) {
            p.period_type.push_back(interactive);
        }
        else if (!p.up_state[i] && p.down_state[i]) {
            p.period_type.push_back(download);
        }
        else if (p.up_state[i] && !p.down_state[i]) {
            p.period_type.push_back(upload);
        }
        else {
            p.period_type.push_back(none);
            null_counter++;
        }
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


void Statistic_analysis::process_dead_sessions(int current_time) {
    //cout << "Starting_to_process..." << endl;
    //cout << "Size of map before " << pack_time.size() << endl;
    map<Session, Packages>::iterator it = pack_time.begin();
    while (it != pack_time.end()) {
            if (!it->second.is_alive(current_time)) {
                dead_session_inform(it->first);
                fill_if_not_equal(it->second);
                if (fill_state(it->second) && fill_period_type(it->second)) {
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
         if (fill_state(it->second) && fill_period_type(it->second)) { 
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
        Session temp_ses2(p);
        temp_ses2.session_reverse();
        map<Session, Packages>::iterator it = pack_time.find(temp_ses);
        map<Session, Packages>::iterator it2 = pack_time.find(temp_ses2);

        
        if (it != pack_time.end()) {
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
        else if (it2 != pack_time.end()) {
            if (it2->second.up_init_sec == 0) it2->second.up_init_sec = p_time;
            if (p_time > it2->second.down_prev_sec + 1 && it2->second.down_prev_sec != -1 ) {
                int j;
                for (j = 0; j < p_time - it2->second.down_prev_sec  - 1; j++) {
                   it2->second.downlink.push_back(0);
                }
                //it2->second.down_prev_sec = p_time;
            }
            if (it2->second.down_prev_sec == (int)(p_time)) {
                it2->second.downlink[it2->second.downlink.size() - 1] += p_size;
            }
            else {
                 it2->second.down_prev_sec = p_time;
                 it2->second.downlink.push_back(p_size);
            }
        }
        else {
          // ?  pack_time[temp_ses].ip = p_ip;
            pack_time[temp_ses].uplink.push_back(p_size);
            pack_time[temp_ses].up_init_sec = p_time;
            pack_time[temp_ses].up_prev_sec = p_time;
        }
        

}

void Statistic_analysis::print_map() {
    ofstream out("result/mymap.txt");
    out << "MAP SIZE " << pack_time.size();
    map<Session, Packages>::iterator it;
    for(it = pack_time.begin(); it != pack_time.end(); it++) {
        out << "src_ip " << inet_ntoa(it->first.ip_src) << endl;
        out << "dst_ip " << inet_ntoa(it->first.ip_dst) << endl;
        out << "src_port " << ntohs(it->first.port_src) << endl;
        out << "dst_port " << ntohs(it->first.port_dst) << endl;
        switch(it->first.protocol) {
            case IPPROTO_TCP:
                out << "TCP" << endl;
                break;
            case IPPROTO_UDP:
                out << "UDP" << endl;
                break;
        }
        out << it->second.uplink.size() << endl;
        out << it->second.downlink.size() << endl;
    }
    out.close();
}

void Statistic_analysis::dead_session_inform(const Session & ses) const {
    cout << "Session from ip " << inet_ntoa(ses.ip_src);
    cout << " to " << inet_ntoa(ses.ip_dst);
    cout << "  IS DEAD" << endl << endl;
    
}

void Statistic_analysis::write_session_to_file(Session first, Packages second) {   
    if (second.downlink.size() < 3 || second.uplink.size() < 3) { return; }
    string file_name = "result/ses" + to_string(processed_sessions_counter) + "_uplink.txt";
    ofstream out_up(file_name);
    
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

void Statistic_analysis::write_map() {
    cout << "size = " << pack_time.size() << endl;
    map<Session, Packages>::iterator it;
    int counter = 0;
    for(it = pack_time.begin(); it != pack_time.end(); it++) {
        string uplink_file_name = "ses_" + to_string(counter) + "_uplink.txt";
        ofstream out_up(uplink_file_name);
        cout << "session number " << counter << " ip_src " << inet_ntoa(it->first.ip_src) << endl;
        for (int i = 0; i < it->second.uplink.size(); i++) {
                out_up << i << " " << it->second.uplink[i] << endl;
        }
        out_up.close();
        string downlink_file_name = "ses_" + to_string(counter) + "_downlink.txt";
        ofstream out_down(downlink_file_name);
        for (int i = 0; i < it->second.downlink.size(); i++) {
                out_down << i << " " << it->second.downlink[i] << endl;
                out_down << i + 1 << " " << it->second.downlink[i] << endl;
        }
        out_down.close();
        counter++;
    }
}


