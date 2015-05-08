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
    Working_classes wc;
    //Config* config = Config::get_config();
    Net_sniffer *n_sniffer;
    try {
        TCLAP::CmdLine cmd("Command description message", ' ', "0.9");
        TCLAP::ValueArg<std::string> mode_arg("m","mode","Mode will be used", false, "live", "string");
        TCLAP::ValueArg<std::string> device_arg("d","device","Device will be cature and sniff or *.pcap file", false, "wlan0", "string");
        cmd.add(mode_arg);
        cmd.add(device_arg);
        cmd.parse(argc, argv);
        string mode = mode_arg.getValue();
        string device = device_arg.getValue();

        if ( mode == "offline") {
            n_sniffer = new Net_sniffer(device.c_str(), filter_expr, false);
        }
        else {
            n_sniffer = new Net_sniffer(device.c_str(), filter_expr, true);
        }
    }
    catch (TCLAP::ArgException &e) {
        cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
    }
    try {
        n_sniffer->start_sniff(&wc);
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
