#ifndef STATISTIC_ANALYSIS_H
#define STATISTIC_ANALYSIS_H
#include <pcap.h>
#include "Packet.h"
#include <map>
#include "Session.h"
#include <vector>
#include <string>
#include "Configuration.h"


enum Traffic_type {
    TYPE_NONE, TYPE_UPLOAD, TYPE_DOWNLOAD, TYPE_INTERACTIVE
};

struct Packages {
    std::vector<int> uplink;
    std::vector<int> downlink;
    std::vector<bool> up_state;
    std::vector<bool> down_state;
    std::vector<Traffic_type> period_type;
    std::vector<double> type_percent;
    int init_sec;
    int last_packet_time();
    bool is_alive(int, int);
    Packages() {
        type_percent.resize(4);
        init_sec = 0;
    }
};



enum Development_mode {MODE_WORKING, MODE_DEBUG};
enum Working_mode {MODE_LEARNING, MODE_DEFINITION};



class Statistic_analysis {
private:
    Config *main_config;
    int process_interval;       //интервал обработки сессий (ищем мертвые и удаляем)
    std::string pcap_filename;  //имя файла, на котором учится программа
    Development_mode dev_mode;
    Working_mode work_mode;

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

    void get_config(std::string name);
    bool process_session(const Session& s, Packages& p);
    void process_dead_sessions(int current_time);
    void process_all_sessions();
    void merge_sessions();
    void move_session(const std::vector<int>& src, const int src_init_sec, std::vector<int>& dst, const int dst_init_sec) ;
    bool fill_state(Packages& p, const std::vector<int>& data, std::vector<bool>& state);
    bool fill_period_type(Packages& p);
    void fill_if_not_equal(Packages& p); //если размеры uplink и downlink не равны, дозаполним меньший нулями
    void add_second(std::vector<int>& v, Packages& p, int p_time, int size);
    std::string get_nearest(Packages& p) const;

private:
    std::string dbg_result_filename;
    int dbg_processed_sessions_counter;
    void dbg_write_decision(std::string decision) const;
    void dbg_write_session_to_file(const Session& first, const Packages& second) const;
    void dbg_dead_session_inform(const Session& ses) const;


public:

    Statistic_analysis(const std::string& config_xml, const std::string& stage, const std::string& working_mode, const std::string& learning_type, const std::string& device);
    ~Statistic_analysis();
    void add_packet(const Packet* p);
    bool hosts_equal(Session const &s1, Session const &s2) const;
};


#endif
