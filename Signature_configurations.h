#ifndef Signature_configurations_H
#define Signature_configurations_H

#include <string>
#include "tinyxml/tinyxml.h"
#include "tinyxml/tinystr.h"

class Signature_configurations {
private:
	//EL: string
    char file_name[100];
    bool in_process;
    TiXmlDocument document;
    TiXmlElement *current_element;
public:
	//EL: лучше сделать метод bool load(...)
    Signature_configurations(const char* f_name);

    bool get_next_signature(std::string& signature, std::string& type, int *priority, int* num_pack);

    bool get_next_param(std::string& type, std::string& f_name, int *args);

    bool is_ready() { return !in_process; }
};

#endif
