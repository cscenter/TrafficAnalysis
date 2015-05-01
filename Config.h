#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "tinyxml/tinyxml.h"
#include "tinyxml/tinystr.h"

class Config {
private:
	//EL: string
    char file_name[100];
    bool in_process;
    TiXmlDocument document;
    TiXmlElement *current_element;
public:
	//EL: лучше сделать метод bool load(...)
    Config(const char* f_name);

    bool get_next_signature(std::string& signature, std::string& type, int *priority);

    bool is_ready() { return !in_process; }
};

#endif
