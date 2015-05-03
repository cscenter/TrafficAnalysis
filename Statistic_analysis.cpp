#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <climits>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "Statistic_analysis.h"


using namespace std;

Statistic_analysis::Statistic_analysis() {
    load_xml("xml/configurations.xml");
    processed_sessions_counter = 0;
    last_process_time = 0;
    if (dev_mode == MODE_DEBUG) {
        mkdir("result", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

}
void Statistic_analysis::load_xml(string name) {
    const int int_settings_number = 5;
    const int string_settings_number = 7;
    const int params_number = 4;
    static MainConfig c(name);
    Config *main_config = c.get_config(name);
    main_config->load_xml_file();
    string *args = new string[string_settings_number];
    int * params = new int[int_settings_number];
    bool state = main_config->get_stat_config(args, params);
    dev_mode = (args[1] == "debug") ? MODE_DEBUG :MODE_WORKING;
    pcap_filename = args[2];
    result_filename = args[3];
    work_mode = (args[4] == "learning") ? MODE_LEARNING : MODE_DEFINITION;
    learning_type = args[5];
    in_addr temp;
    int t = inet_aton(args[6].c_str(), &temp);
    host_ip = temp.s_addr;
    state_period = params[0];
    state_limit = params[1];
    session_time_limit = params[2];
    none_limit = (double) params[3] / 100;
    config = c.get_config(args[0]);
    config->load_xml_file();
    if (work_mode == MODE_DEFINITION) {
        while (!config->is_ready()) {
            string type;
            double *data = new double[params_number];
            config->get_next_param(type, data);
            vector<double> v(data, data + params_number);
            statistic_data.insert(pair<string, vector<double> >(type, v));
        }
    }
}




bool Statistic_analysis::fill_state(Packages& p, const vector<int> & v, vector<bool>& state) {

	int false_counter = 0, sum = 0;
    for (int i = 0; i < v.size(); i++) {
        sum += v[i];
		if ((i + 1) % state_period == 0 || i == v.size() - 1) {
		    if (sum > state_limit) {
			    state.push_back(true);
		    }
		    else {
                false_counter++;
			    state.push_back(false);
		    }
		    sum = 0;
	    }
    }

	if (false_counter == state.size()) return false;
	return true;
}

bool Statistic_analysis::fill_period_type(Packages& p) {
    static int counter = 0;
    counter++;
    int null_counter = 0;
    traffic_type tr_t;
    for (int i = 0; i < p.up_state.size(); i++) {
        if (p.up_state[i] && p.down_state[i]) {
            tr_t = TYPE_INTERACTIVE;
        }
        else if (!p.up_state[i] && p.down_state[i]) {
            tr_t = TYPE_DOWNLOAD;
        }
        else if (p.up_state[i] && !p.down_state[i]) {
            tr_t = TYPE_DOWNLOAD;
        }
        else {
            tr_t = TYPE_NONE;
            null_counter++;
        }
        p.period_type.push_back(tr_t);
        p.type_percent[(int)tr_t]++;
    }

    for (int i = 0; i < p.type_percent.size(); i++) {
        p.type_percent[i] /= p.up_state.size();
    }
    if (p.type_percent[TYPE_NONE] > none_limit) return false;
    return true;
}


 			

void Statistic_analysis::fill_if_not_equal(Packages& p) {
    if (p.downlink.size() > p.uplink.size()) p.uplink.resize(p.downlink.size());
    else if (p.downlink.size() < p.uplink.size()) p.downlink.resize(p.uplink.size());
}


bool Statistic_analysis::process_session(const Session& s, Packages& p) {
    fill_if_not_equal(p);
    bool flag1 = fill_state(p, p.uplink, p.up_state);
    bool flag2 = fill_state(p, p.downlink, p.down_state);
    if ((flag1 || flag2) && fill_period_type(p)
        && (p.downlink.size() >= session_time_limit && p.uplink.size() >= session_time_limit )) {
            if (dev_mode == MODE_DEBUG) write_session_to_file(s, p);
            if (work_mode == MODE_LEARNING) config->write_stat_to_xml(learning_type, pcap_filename, p.type_percent);
            if (work_mode == MODE_DEFINITION) {
                string decision = get_nearest(p);
                write_decision(decision);
            }
            processed_sessions_counter++;
        }

    processed_sessions_counter++;
}


void Statistic_analysis::write_decision(string decision) {
    cout << "HEAR" << endl;
    ofstream out_up(result_filename, ios::app);
    out_up << pcap_filename << " " << decision << endl;
}

void Statistic_analysis::process_dead_sessions(int current_time) {
    cout << " I WAS HEAR" << endl;
    auto it = pack_time.begin();
    while (it != pack_time.end()) {
        if (!it->second.is_alive(current_time, time_to_live)) {
            process_session(it->first, it->second);
            pack_time.erase(it++);
        }
        else it++;
    }
}


void Statistic_analysis::process_all_sessions() {
    auto it = pack_time.begin();
    while (it != pack_time.end()) {
        process_session(it->first, it->second);
        pack_time.erase(it++);
    }

}


bool Packages::is_alive(int current_time, int time_to_live) {
    return (current_time - last_packet_time()) < time_to_live;
}

int Packages::last_packet_time() {
    return (uplink.size() > downlink.size()) ? uplink.size() + init_sec : downlink.size() + init_sec;
}




void Statistic_analysis::add_second(vector<int>& v, Packages& p, int p_time, int size) {
    if (p.init_sec == 0) p.init_sec = p_time;
    if (p_time > p.init_sec + v.size() - 1) {
        v.resize(p_time - p.init_sec + 1);
    }
    v[v.size() - 1] += size;
}

void Statistic_analysis::add_packet(const Packet& p) {   //FILL MAP
    int p_time = p.get_header().ts.tv_sec;
    if (p_time - last_process_time > process_interval && last_process_time != 0) {
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

    if (!is_reversed && it != pack_time.end()) {   //пришел пакет в uplink
        add_second(it->second.uplink, it->second, p_time, p_size);

    } else if (is_reversed && it != pack_time.end()) {   //пришел пакет в downlink
        add_second(it->second.downlink, it->second, p_time, p_size);
    } else {
        Packages& new_ses = pack_time[temp_ses];
        if (!is_reversed) {
            add_second(new_ses.uplink, new_ses, p_time, p_size);
        }
        else {
            add_second(new_ses.downlink, new_ses, p_time, p_size);
        }
    }

}


void Statistic_analysis::dead_session_inform(const Session & ses) const {
    cout << "Session from ip " << inet_ntoa(ses.ip_src);
    cout << " to " << inet_ntoa(ses.ip_dst) << " ";
    cout << ses.port_src << " ";
    cout << ses.port_dst << " ";
    cout << "  IS DEAD" << endl << endl;
    
}


bool Statistic_analysis::hosts_equal(Session const &s1, Session const &s2) {
    if (s1.ip_src.s_addr == s2.ip_src.s_addr && s1.ip_dst.s_addr == s2.ip_dst.s_addr) {
        return true;
    }
    return false;
}


void Statistic_analysis::move_session(const vector<int>& src, const int src_init_sec,
                                      vector<int>& dst, const int dst_init_sec) {

    if (src_init_sec + src.size() - dst_init_sec > dst.size()) {
        dst.resize(src_init_sec + src.size() - dst_init_sec);
    }
    for (int i = 0; i < src.size(); i++) {
        dst[src_init_sec - dst_init_sec + i] += src[i];
    }
}

void Statistic_analysis::merge_sessions() {
    auto prev = pack_time.begin();
    auto cur = pack_time.begin();
    cur++;
    bool flag = false;
    while (cur != pack_time.end()) {
        if (hosts_equal(prev->first, cur->first)) {
            if (cur->second.init_sec < prev->second.init_sec) { // сессия cur началась раньше
                move_session(prev->second.uplink, prev->second.init_sec, cur->second.uplink, cur->second.init_sec);
                move_session(prev->second.downlink, prev->second.init_sec, cur->second.downlink, cur->second.init_sec);
                pack_time.erase(prev++);
                cur++;
            }
            else {
                move_session(cur->second.uplink, cur->second.init_sec, prev->second.uplink, prev->second.init_sec);
                move_session(cur->second.downlink, cur->second.init_sec, prev->second.downlink, prev->second.init_sec);
                pack_time.erase(cur++);
            }
        }
        else {
            prev = cur;
            cur++;
        }
    }
}
Statistic_analysis::~Statistic_analysis() {
    merge_sessions();
    process_all_sessions();
}

string Statistic_analysis::get_nearest(Packages& p) {
    int min = INT_MAX;
    string min_name;
    for(auto it : statistic_data) {
        double d = 0;
        for (int j = 0; j < p.type_percent.size(); j++) {
            d += (p.type_percent[j] - it.second[j]) * (p.type_percent[j] - it.second[j]);
        }
        if (d < min) {
            min_name = it.first;
            min = d;
        }
    }
    return min_name;
}

void Statistic_analysis::write_session_to_file(const Session& first, const Packages& second) {
    string file_name = "result/ses" + to_string(processed_sessions_counter) + "_uplink.txt";
    ofstream out_up(file_name);
    /*out_up << first.ip_src.s_addr << endl;
    out_up << " to " << first.ip_dst.s_addr << endl;
    out_up << first.port_src <<  " " << first.port_dst << endl;
    switch(first.protocol) {
        case IPPROTO_TCP:
            out_up << "TCP" << endl;
            break;
        case IPPROTO_UDP:
            out_up << "UDP" << endl;
            break;
    }
    */
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
    int period = state_period;
    file_name = "result/ses" + to_string(processed_sessions_counter) + "_up_state.txt";
    ofstream out_up_state(file_name);
    if (second.up_state.size() != 0) out_up_state << 0 << " " << second.up_state[0] << endl;

    for (int i = 0; i < second.up_state.size(); i++) {
        out_up_state << (i + 1) * period - 1 << " " << second.up_state[i] << endl;
    }
    out_up_state.close();

    file_name = "result/ses" + to_string(processed_sessions_counter) + "_down_state.txt";
    ofstream out_down_state(file_name);
    if (second.down_state.size() != 0) out_down_state << 0 << " " << second.down_state[0] << endl;
    for (int i = 0; i < second.down_state.size(); i++) {
        out_down_state << (i + 1) * period - 1 << " " << second.down_state[i] << endl;
    }
    out_down_state.close();

    file_name = "result/ses" + to_string(processed_sessions_counter) + "_period_types.txt";
    ofstream out_period_types(file_name);

    if (second.period_type.size() != 0) out_period_types << 0 << " " << second.period_type[0] << endl;
    for (int i = 0; i < second.period_type.size(); i++) {
        out_period_types << (i + 1) * period - 1 << " " << second.period_type[i] << endl;
        out_period_types << (i + 1) * period - 1 << " " << second.period_type[i] << endl;
    }
    out_period_types.close();

}
