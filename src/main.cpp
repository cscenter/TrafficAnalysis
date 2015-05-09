#include <iostream>
#include <new>
#include <stdlib.h>
#include <fstream>
#include <tclap/CmdLine.h>


#include "Net_sniffer.h"
#include "Signature_analysis.h"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define UDP_LENGTH 8

using namespace std;

//EL: проверить на const у параметров и у МЕТОДОВ!

//EL: убрать одинаковые куски

int main(int argc, char **argv) {
    string filter_expr = "ip";
    //Config* config = Config::get_config();
    Net_sniffer *n_sniffer;
    try {
        TCLAP::CmdLine cmd("Command description message", ' ', "0.9");
        vector<string> allowed(2);
        allowed[0] = "live";
        allowed[1] = "offline";
        TCLAP::ValuesConstraint<string> allowedVals( allowed );;
        TCLAP::ValueArg<std::string> mode_arg("m","mode","Set mode", false, "live", &allowedVals);
        TCLAP::ValueArg<std::string> device_arg("d","device","Set the device or *.pcap file", false, "wlan0", "string");
        allowed[0] = "determine";
        allowed[1] = "learn";
        TCLAP::ValuesConstraint<string> allowedVals2( allowed );;
        TCLAP::ValueArg<std::string> work_mode_arg("a","action","Set the action", false, "determine", &allowedVals2);
        TCLAP::ValueArg<std::string> learning_type_arg("t","type","Set the learning type", false, "browsing", "string");
        allowed[0] = "debug";
        allowed[1] = "release";
        TCLAP::ValuesConstraint<string> allowedVals3( allowed );;
        TCLAP::ValueArg<std::string> dev_stage_arg("s","stage","Set the stage", false, "debug", &allowedVals3);
        TCLAP::ValueArg<std::string> config_filename_arg("c","config_filename","Enter config filename",
                                                     false, "xml/configurations.xml", "string");
        cmd.add(mode_arg);
        cmd.add(device_arg);
        cmd.add(work_mode_arg);
        cmd.add(dev_stage_arg);
        cmd.add(learning_type_arg);
        cmd.add(config_filename_arg);
        cmd.parse(argc, argv);
        string mode = mode_arg.getValue();
        string device = device_arg.getValue();
        Working_classes wc(config_filename_arg.getValue(), dev_stage_arg.getValue(), work_mode_arg.getValue(),
                           learning_type_arg.getValue(), device_arg.getValue());
        if (mode == "offline") {
            n_sniffer = new Net_sniffer(device.c_str(), filter_expr, false);
        }
        else {
            n_sniffer = new Net_sniffer(device.c_str(), filter_expr, true);
        }
        n_sniffer->start_sniff(&wc);
    }
    catch (TCLAP::ArgException &e) {
        cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
    }
    catch (Net_sniffer_exception e) {
        cout << e.get_exception_reason() << endl;
    }
    delete n_sniffer;

}



/*

    if (argc == 2) {
        Net_sniffer *obj = new Net_sniffer(argv[1], filter_expr, true);
        try {
            obj->start_sniff(&wc);
        }
        catch (Net_sniffer_exception e) {
            cout << e.get_exception_reason() << endl;
        }
        delete obj;
    }
    else {
        if (argc == 3) {
            bool mode = true;
            if (strcmp(argv[2], "offline") == 0) {
                mode = false;
            }
            Net_sniffer *obj = new Net_sniffer(argv[1], filter_expr, mode);
            try {
                obj->start_sniff(&wc);
            }
            catch (Net_sniffer_exception e) {
                cout << e.get_exception_reason() << endl;
            }
            delete obj;
        }
        else {
            if (argc > 3) {
                cout << "error: unrecognized command-line options\n" << endl;
                return 0;
            }
            else {
                Net_sniffer *obj = new Net_sniffer();
                try {
                    obj->start_sniff(&wc);
                }
                catch (Net_sniffer_exception e) {
                    cout << e.get_exception_reason() << endl;
                }
                delete obj;
            }
        }
    }
    return 0;
};*/
