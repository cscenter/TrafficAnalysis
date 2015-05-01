#include <iostream>
#include <stdio.h>

#include "Signature_configurations.h"

using namespace std;

Signature_configurations::Signature_configurations(const char* f_name) {
    in_process = true;
    strcpy(file_name, f_name);
    bool load_status = document.LoadFile(file_name, TIXML_DEFAULT_ENCODING);
    //EL:  вернуть код ошибки; здесь такое решение принять невозможно
    if (!load_status) {
        cout << "Have a load mistake!!!" << endl;
        exit(0);
    }
    current_element = document.RootElement()->FirstChildElement();
}

bool Signature_configurations::get_next_signature(string& signature, string& type, int *priority, int *num_pack) {
    if (!in_process) {
        return false;
    }
    TiXmlAttribute *atr = current_element->FirstAttribute();
    int atr_num = 1;
    while (atr != NULL) {
        //string atr_name(atr->Name());
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
                                  cout << "Tiny problem!!!" << endl;
                                  return false;
                              }
                              break;
            case 4 : int num;
                              if (atr->QueryIntValue(&num) == TIXML_SUCCESS) {
                                  *num_pack = num;
                              }
                              else {
                                  cout << "Tiny problem!!!" << endl;
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


bool Signature_configurations::get_next_param(string& type, string& f_name, int *args) {
   if (!in_process) {
        return false;
    }
    TiXmlAttribute *atr = current_element->FirstAttribute();
    int atr_num = 1;
    while (atr != NULL) {
        //string atr_name(atr->Name());
        switch(atr_num) {
            case 1 : type = *(new string(atr->Value()));
                          break;
            case 2 : f_name = *(new string(atr->Value()));
                          break;
            default : int pr;
                      if (atr->QueryIntValue(&pr) == TIXML_SUCCESS) {
                          args[atr_num - 1] = pr;
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




 /*

    TiXmlAttribute *atr = current_element->FirstAttribute();
    if (atr == NULL) {
        return false;
    }




    signature = *(new string(atr->Value());

    atr = atr->Next();
    if (atr == NULL) {
        return false;
    }
    type = *(new string(atr->Value()));

    atr = atr->Next();
    if (atr == NULL) {
        return false;
    }
    int pr;
    if (atr->QueryIntValue(&pr) == TIXML_SUCCESS) {
        *priority = pr;
    }
    else {
        cout << "Tiny problem!!!" << endl;
        return false;
    }


    current_element = current_element->NextSiblingElement();
    if (current_element == NULL) {
        in_process = false;
    }

    return true;
}
*/
