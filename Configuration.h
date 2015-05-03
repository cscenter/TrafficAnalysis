#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "tinyxml/tinyxml.h"
#include "tinyxml/tinystr.h"
#include <vector>
class Config {
private:
    static Config *config;
    std::string file_name;
    bool in_process;
    TiXmlDocument document;
    TiXmlElement *current_element;
protected:
    Config(std::string f_name);
    ~Config() { delete config;}
public:
    static Config* get_config(std::string f_name) { return new Config(f_name); }

    bool load_xml_file();

    bool get_sign_config(std::string *config_list);

    bool get_next_param(std::string& type, double *args);

    bool get_next_signature(std::string& signature, std::string& type, int *priority, int *num_pack);

    bool is_ready() const { return !in_process; }

    void write_stat_to_xml(const std::string& traffic_type, const std::string& pcap_filename,
                                                 const std::vector<double>& data);
    bool get_stat_config(std::string *config_list, int * params);
};


class MainConfig : public Config {
public:
    MainConfig(std::string f_name) : Config(f_name){
        Config::get_config(f_name);
    }

    ~MainConfig() {};
};



#endif