#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "tinyxml/tinyxml.h"
#include "tinyxml/tinystr.h"

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

    bool get_next_param(std::string& type, std::string& f_name, int *args);

    bool get_next_signature(std::string& signature, std::string& type, int *priority, int *num_pack);

    bool is_ready() const { return !in_process; }
};


class MainConfig : public Config {
public:
    MainConfig(std::string f_name) : Config(f_name){
        Config::get_config(f_name);
    }

    ~MainConfig() {};
};



#endif
