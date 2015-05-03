#include <iostream>
#include <stdio.h>

#include "Configuration.h"

using namespace std;

Config* Config::config = 0;

Config::Config(std::string f_name) : file_name(f_name) {}

bool Config::load_xml_file() {
    in_process = true;
    bool load_status = document.LoadFile(file_name.c_str(), TIXML_DEFAULT_ENCODING);
    if (!load_status) {
        return false;
    }
    current_element = document.RootElement()->FirstChildElement();
    return true;
}

bool Config::get_next_signature(string& signature, string& type, int *priority, int *num_pack) {
    if (!in_process) {
        return false;
    }
    TiXmlAttribute *atr = current_element->FirstAttribute();
    int atr_num = 1;
    while (atr != NULL) {
        switch(atr_num) {
            case 1 : signature = *(new string(atr->Value()));
                          break;
            case 2 : type = *(new string(atr->Value()));
                          break;
            case 3 : int pr;
                              if (atr->QueryIntValue(&pr) == TIXML_SUCCESS) {
                                  *priority = pr;
                              }
                              else {
                                  return false;
                              }
                              break;
            case 4 : int num;
                              if (atr->QueryIntValue(&num) == TIXML_SUCCESS) {
                                  *num_pack = num;
                              }
                              else {
                                  return false;
                              }
                              break;
            default : return false;
        }
        atr = atr->Next();
        atr_num++;
    }
    current_element = current_element->NextSiblingElement();
    if (current_element == NULL) {
        in_process = false;
    }
    return true;
}

bool Config::get_next_param(string& type, string& f_name, int *args) {
   if (!in_process) {
        return false;
    }
    TiXmlAttribute *atr = current_element->FirstAttribute();
    int atr_num = 1;
    while (atr != NULL) {
        switch(atr_num) {
            case 1 : type = *(new string(atr->Value()));
                     break;
            case 2 : f_name = *(new string(atr->Value()));
                     break;
            default : int pr;
                      if (atr->QueryIntValue(&pr) == TIXML_SUCCESS) {
                          args[atr_num - 3] = pr;
                      }
                      else {
                          cout << "Tiny problem!!!" << endl;
                          return false;
                      }
                      break;
        }
        atr = atr->Next();
        atr_num++;
    }
    current_element = current_element->NextSiblingElement();
    if (current_element == NULL) {
        in_process = false;
    }
    return true;
}

bool Config::get_sign_config(string *config_list) {
    while ( strcmp(current_element->Value(),"sign_config") != 0) {
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
    }
    return true;
}
