#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "tinyxml/tinyxml.h"
#include "tinyxml/tinystr.h"

class Config {
private:
    static Config *config;
protected:
    char file_name[100];
    bool in_process;
    TiXmlDocument document;
    TiXmlElement *current_element;
    Config(const char* f_name);
public:
    static Config* get_config(const char* f_name) {
        if (config == 0) {
            config = new Config(f_name);
        }
        return config;
    }

    bool get_sign_config(std::string *config_list);

    bool is_ready() { return !in_process; }
};


class MainConfig : public Config {
public:
    MainConfig(const char* f_name) : Config(f_name){
        Config::get_config(f_name);
    }
};



#endif
