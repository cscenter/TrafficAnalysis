#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "tinyxml/tinyxml.h"
#include "tinyxml/tinystr.h"

class Config {
private:
    char file_name[100];
    bool in_process;
    TiXmlDocument document;
    TiXmlElement *current_element;
public:

    Config(const char* f_name);

    bool get_next_signature(std::string& signature, std::string& type);

    bool is_ready() { return !in_process; }
};

#endif
