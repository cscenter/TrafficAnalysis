#ifndef STATISTIC_ANALYSIS_H
#define STATISTIC_ANALYSIS_H
#include <pcap.h>
#include "Packet.h"
#include <map>
#include "Session.h"
#include <vector>
#include <string>
#include "Configuration.h"

//EL: в остальном коде имена типов написаны с большой буквы, например, Packages
enum traffic_type {
    TYPE_NONE, TYPE_UPLOAD, TYPE_DOWNLOAD, TYPE_INTERACTIVE
};

struct Packages {
    std::vector<int> uplink;
    std::vector<int> downlink;
    std::vector<bool> up_state;
    std::vector<bool> down_state;
    std::vector<traffic_type> period_type;
    std::vector<double> type_percent;
    int init_sec;
    int last_packet_time();
    bool is_alive(int, int);
    Packages() {
        type_percent.resize(4);
        init_sec = 0;
    }
};


/*
 * 	<stat_config file_name="xml/stat.xml" mode="debug" mode="learning"
                 pcap_mode="browsing" host_ip="192.168.101.100"
                 state_period = "3" state_limit = "128"
                 session_time_limit="30" none_limit="0.8"  />

 */

enum development_mode {MODE_WORKING, MODE_DEBUG};
enum working_mode {MODE_LEARNING, MODE_DEFINITION};


//EL: в объявлении класса отделить префиксом (например, dbg_) и 
//EL: положением в класее методы и поля, которые используются только 
//EL: в режиме debug
class Statistic_analysis {
    Config *main_config;
    int processed_sessions_counter;
    int process_interval;       //интервал обработки сессий (ищем мертвые и удаляем)
    std::string pcap_filename;  //имя файла, на котором учится программа
    development_mode dev_mode;
    working_mode work_mode;
    std::string result_filename;
    std::string learning_type; //тип трафика, которому учится программа
    int state_period;         //период в секундах
    int state_limit;          //граница в байтах (есть/нет трафик в периоде)
    int session_time_limit;   //минимальная длительность сессии
    double none_limit;           //минимальная граница состояния "none" для сессии в процентах
    int time_to_live;         //время жизни сессии
    int host_ip;
    int last_process_time;    //время последней обработки сессии
    std::map<Session, Packages> pack_time;
    std::multimap<std::string, std::vector<double> >  statistic_data;
    void write_session_to_file(const Session& first, const Packages& second);
    bool process_session(const Session& s, Packages& p);
    void process_dead_sessions(int current_time);
    void process_all_sessions();
    void merge_sessions();
    void move_session(const std::vector<int>& src, const int src_init_sec, std::vector<int>& dst, const int dst_init_sec) ;
    void dead_session_inform(const Session& ses) const;
    bool fill_state(Packages& p, const std::vector<int>& data, std::vector<bool>& state);
    bool fill_period_type(Packages& p);
    void fill_if_not_equal(Packages& p); //если размеры uplink и downlink не равны, дозаполним меньший нулями
    void load_xml(std::string name);
    bool hosts_equal(const Session & s1, const Session & s2) const;
    void write_to_xml(std::string filename, std::string traffic_type);
    void add_second(std::vector<int>& v, Packages& p, int p_time, int size);
    std::string get_nearest(Packages& p);
    void write_decision(std::string decision);



public:
    //Statistic_analysis();
    Statistic_analysis(const std::string& config_xml, const std::string& stage, const std::string& working_mode, const std::string& learning_type, const std::string& device);

    ~Statistic_analysis();

    void add_packet(const Packet* p);

    bool hosts_equal(Session const &s1, Session const &s2);
};


#endif
