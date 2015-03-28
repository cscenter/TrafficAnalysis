#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>
#include <string>
#include <ctype.h>
#include <errno.h>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include <time.h>

#include "StatisticAnalysis.h"

using namespace std;

StatisticAnalysis::StatisticAnalysis(allPackets p) {   //FILL MAP
        int i;
//	cout << " !" << endl<<endl<<endl<<endl;	
        for (i = 0; i < p.v.size(); i++) {
            Session temp_ses, temp_ses2;
            temp_ses.ip_src = p.v[i].ip.ip_src;
            temp_ses.ip_dst = p.v[i].ip.ip_dst;
            temp_ses.protocol = p.v[i].ip.ip_p;
            temp_ses2.ip_src = p.v[i].ip.ip_dst;
            temp_ses2.ip_dst = p.v[i].ip.ip_src;
            temp_ses2.protocol = p.v[i].ip.ip_p;
            switch(p.v[i].ip.ip_p) {
                case IPPROTO_TCP:
                    temp_ses.port_src = p.v[i].tcp.th_sport;
                    temp_ses.port_dst = p.v[i].tcp.th_dport;
                    temp_ses2.port_src = p.v[i].tcp.th_dport;
                    temp_ses2.port_dst = p.v[i].tcp.th_sport;
                    break;
                case IPPROTO_UDP:
                    temp_ses.port_src = p.v[i].udp.s_port;
                    temp_ses.port_dst = p.v[i].udp.d_port;
                    temp_ses2.port_src = p.v[i].udp.d_port;
                    temp_ses2.port_dst = p.v[i].udp.s_port;
                    break;
            }
            map<Session, Packages>::iterator it = PackagesTime.find(temp_ses);
            map<Session, Packages>::iterator it2 = PackagesTime.find(temp_ses2);


            if (it != PackagesTime.end()) {
                if (p.v[i].header.ts.tv_sec > it->second.up_prev_sec + 1 && it->second.up_prev_sec != -1 ) {
                    int j;
		 	
                    for (j = 0; j < p.v[i].header.ts.tv_sec - it->second.up_prev_sec  - 1; j++) {
                        it->second.uplink.push_back(0);
                    }
                   // it->second.up_prev_sec = p.v[i].header.ts.tv_sec;
                }
                if (it->second.up_prev_sec  == (int)(p.v[i].header.ts.tv_sec)) it->second.uplink[it->second.uplink.size() - 1]++;
                else {
                    it->second.up_prev_sec = p.v[i].header.ts.tv_sec;
                    it->second.uplink.push_back(1);
                }
            }
            else if (it2 != PackagesTime.end()) {
                if (it2->second.up_init_sec == 0) it2->second.up_init_sec = p.v[i].header.ts.tv_sec;
		//cout << "c ! "<< p.v[i].header.ts.tv_sec << " " << it2->second.down_prev_sec << endl;	
                if (p.v[i].header.ts.tv_sec > it2->second.down_prev_sec + 1 && it2->second.down_prev_sec != -1 ) {
                    int j;
	            //cout << p.v[i].size_ip;// << " " << it2->second.down_prev_sec << endl;			
                    for (j = 0; j < p.v[i].header.ts.tv_sec - it2->second.down_prev_sec  - 1; j++) {
                       it2->second.downlink.push_back(0);
                    }
                    //it2->second.down_prev_sec = p.v[i].header.ts.tv_sec;
                }
                if (it2->second.down_prev_sec == (int)(p.v[i].header.ts.tv_sec)) it2->second.downlink[it2->second.downlink.size() - 1]++;
                else {
                     it2->second.down_prev_sec = p.v[i].header.ts.tv_sec;
                     it2->second.downlink.push_back(1);
                }
            }
            else {
                PackagesTime[temp_ses].ip = p.v[i].ip;
                PackagesTime[temp_ses].uplink.push_back(1);
                PackagesTime[temp_ses].up_init_sec = p.v[i].header.ts.tv_sec;
                PackagesTime[temp_ses].up_prev_sec = p.v[i].header.ts.tv_sec;
            }
        }


}

void StatisticAnalysis::print_map() {
	cout << "MAP SIZE " << PackagesTime.size();
	map<Session, Packages>::iterator it;
	for(it = PackagesTime.begin(); it != PackagesTime.end(); it++) {
		cout << "src_ip " << inet_ntoa(it->first.ip_src) << endl;
		cout << "dst_ip " << inet_ntoa(it->first.ip_dst) << endl;
		cout << "src_port " << ntohs(it->first.port_src) << endl;
		cout << "dst_port " << ntohs(it->first.port_dst) << endl;
		cout << it->second.uplink.size() << endl;
		cout << it->second.downlink.size() << endl;
	}
}


void StatisticAnalysis::write_map() {
    cout << "size = " << PackagesTime.size() << endl;
	map<Session, Packages>::iterator it;
	int counter = 0;
	for(it = PackagesTime.begin(); it != PackagesTime.end(); it++) {
		string uplink_file_name = "ses_" + to_string(counter) + "_uplink.txt";
		ofstream out_up(uplink_file_name);
		cout << "session number " << counter << " ip_src " << inet_ntoa(it->first.ip_src) << endl;
		for (int i = 0; i < it->second.uplink.size(); i++) {
	    		out_up << i << " " << it->second.uplink[i] << endl;
		}
		out_up.close();
		string downlink_file_name = "ses_" + to_string(counter) + "_downlink.txt";
		ofstream out_down(downlink_file_name);
		for (int i = 0; i < it->second.downlink.size(); i++) {
	    		out_down << i << " " << it->second.downlink[i] << endl;
		}
		out_down.close();
		counter++;
	}
}


