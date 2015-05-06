#include <iostream>
#include <stdio.h>

#include "Configuration.h"

using namespace std;

Config* Config::config = 0;

bool Config::load_xml_file(const string &f_name) {
    file_name = f_name;
    in_process = true;
    bool load_status = document.LoadFile(file_name.c_str(), TIXML_DEFAULT_ENCODING);
    if (!load_status) {
        return false;
    }
    current_element = document.RootElement()->FirstChildElement();
    return true;
}

bool Config::next_tag() {
    if (current_element->NextSiblingElement() == NULL) {
        current_element = current_element->Parent()->NextSiblingElement();
        while (current_element != NULL) {
            if (!current_element->NoChildren()) {
                current_element = current_element->FirstChildElement();
                return true;
            }
        }
        return false;
    }
    else {
        current_element = current_element->NextSiblingElement();
        return true;
    }
}

bool Config::get_tag(const std::string& name) {
    current_element = document.RootElement();
    while (current_element != NULL) {
        if (!current_element->NoChildren()) {
            current_element = current_element->FirstChildElement();
        }
        while (current_element != NULL) {
            if (strcmp(current_element->Value(), name.c_str()) == 0) {
                return true;
            }
            current_element = current_element->NextSiblingElement();
        }
        current_element = current_element->Parent()->NextSiblingElement();
    }
    return false;
}

bool Config::get_attribute_str(const string& name, string& value) {//, TiXmlElement* element) {
    TiXmlAttribute *attr = current_element->FirstAttribute();
    while (attr != NULL) {
        if (strcmp(attr->Name(), name.c_str()) == 0) {
            value = attr->Value();
            return true;
        }
        attr = attr->Next();
    }
    return false;
}


bool Config::get_attribute_int(const std::string& name, int *value) {
    TiXmlAttribute *attr = current_element->FirstAttribute();
    while (attr != NULL) {
        if (strcmp(attr->Name(), name.c_str()) == 0) {
            if (attr->QueryIntValue(value) == TIXML_SUCCESS) {
                return true;
            }
        }
        attr = attr->Next();
    }
    return false;
}
/*
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

bool Config::get_next_param(string& type, double *args) {
   if (!in_process) {
        return false;
   }
   TiXmlAttribute *atr = current_element->FirstAttribute();
   int atr_num = 1;
   while (atr != NULL) {
        string * s;
        switch(atr_num) {
            case 1 : s = new string(atr->Value());
                     type = *s;
                     delete s;
                     //type = *(new string(atr->Value()));
                     break;
            case 2 : break;
            default : double pr;
                      if (atr->QueryDoubleValue(&pr) == TIXML_SUCCESS) {
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

bool Config::get_stat_config(std::string *config_list, int * params)  {
    while ( strcmp(current_element->Value(),"stat_config") != 0) {
        current_element = current_element->NextSiblingElement();
        if (current_element == NULL) {
            return false;
        }
        break;
    }
    int i = 0;
    for (TiXmlAttribute *atr = current_element->FirstAttribute(); i < 12 ; atr = atr->Next()) {
        if ( atr == NULL) {
            return false;
        }
        if (i < 7) {
            config_list[i++] = *(new string(atr->Value()));
        }
        else {
            int pr;
            if (atr->QueryIntValue(&pr) == TIXML_SUCCESS) {
                params[i - 7] = pr;
                i++;
            }
            else {
                cout << "Tiny problem!!!" << endl;
                return false;
          }
        }
    }
    return true;
}*/

void Config::write_stat_to_xml(const string& traffic_type, const string& pcap_filename,
                                                 const vector<double>& data) {

    TiXmlElement *root = document.RootElement(); //pointer to root element
    TiXmlElement * element = new TiXmlElement( "s" );
    element->SetAttribute("type", traffic_type.c_str());
    element->SetAttribute("file_name", pcap_filename.c_str());
    element->SetDoubleAttribute("none", (double )data[0]);
    element->SetDoubleAttribute("upload", (double)data[1]);
    element->SetDoubleAttribute("download", (double )data[2]);
    element->SetDoubleAttribute("interactive", (double) data[3]);
    for (int i = 0; i < data.size(); i++) {
        cout << data[i] << " ";
    }
    cout << endl;
    root->InsertEndChild( *element);
    document.SaveFile(file_name.c_str());

}
