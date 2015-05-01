#include <iostream>
#include <stdio.h>

#include "Configuration.h"

using namespace std;

Config* Config::config = 0;

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

bool Config::get_sign_config(string *config_list) {
    while ( strcmp(current_element->Value(),"sign_config") != 0) {
    cout << "1. I'm here!!!" << endl;
        current_element = current_element->NextSiblingElement();
        if (current_element == NULL) {
            return false;
        }
        break;
    }
    int i = 0;
    for (TiXmlAttribute *atr = current_element->FirstAttribute(); i < 3 ; atr = atr->Next()) {
        if ( atr == NULL) {
            return false;
        }
        config_list[i++] = *(new string(atr->Value()));
        cout << "Atr " << config_list[i - 1] << endl;
    }
    return true;
}
