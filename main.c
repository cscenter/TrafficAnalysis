#include <stdio.h>
#include <iostream>
#include <new>

#include "Net_sniffer.h"
#include "SignatureAnalisator.h"
//#include "StatisticAnalysis.h"

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define UDP_LENGTH 8

using namespace std;



int main(int argc, char **argv) {
	char protocol[] = "ip";
    All_packets p;
	if (argc == 2) {
			Net_sniffer *obj = new Net_sniffer(argv[1], protocol, 40);
			p = obj->start_sniff();
	}
	else if (argc > 2) {
			fprintf(stderr, "error: unrecognized command-line options\n\n");
			exit(EXIT_FAILURE);
	}
	else {
		Net_sniffer *obj = new Net_sniffer();
        p = obj->start_sniff();
	}

    p.print_vector();

    SignatureAnalisator* sig_analys = new SignatureAnalisator();
    sig_analys->FormMap(p.v);
    sig_analys->PrintMap();
    //StatisticAnalysis * statAnalysis = new StatisticAnalysis(p.v);
    printf("\nCapture complete.s\n");

	return 0;
};
