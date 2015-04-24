#include <iostream>
#include <stdio.h>

#include "Config.h"

using namespace std;

Config::Config(const char* f_name) {
    in_process = true;
    strcpy(file_name, f_name);
    bool load_status = document.LoadFile(file_name, TIXML_DEFAULT_ENCODING);
    if (!load_status) {
        cout << "Have a load mistake!" << endl;
        exit(0);
    }
    current_element = document.RootElement()->FirstChildElement();
}

bool Config::get_next_signature(string& signature, string& type) {
    if (!in_process) {
        return false;
    }
    TiXmlAttribute *atr = current_element->FirstAttribute();
    if (atr == NULL) {
        return false;
    }
    string sign(atr->Value());
    signature = sign;
    atr = atr->Next();
    if ( atr == NULL) {
        return false;
    }
    string t(atr->Value());
    type = t;
    current_element = current_element->NextSiblingElement();
    if (current_element == NULL) {
        in_process = false;
    }
    return true;
}
