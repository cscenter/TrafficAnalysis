#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <new>

#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <string>
#include <time.h>

#include "StatisticAnalysis.h"


StatisticAnalysis::StatisticAnalysis(allPackets p)
{
        cout << " I AM HEAR \n\n\n";
        int i;
        for (i = 0; i < p.v.size(); i++)
        {
            Session temp_ses;
            temp_ses.ip_src = p.v[i].ip -> ip_src;
            temp_ses.ip_dst = p.v[i].ip -> ip_dst;
            temp_ses.port_src = p.v[i].tcp -> th_sport;
            temp_ses.port_dst = p.v[i].tcp -> th_dport;
            temp_ses.protocol = p.v[i].ip -> ip_p;

            map<Session, Packages>::iterator it = PackagesTime.find(temp_ses);
            if (it != PackagesTime.end())
            {
                if (it->first.ip_src.s_addr == temp_ses.ip_dst.s_addr)
                {
                    it->second.downlink.push_back(p.v[i].header->ts.tv_sec);
                }
                else it->second.uplink.push_back(p.v[i].header->ts.tv_sec);
            }
            else
            {
                PackagesTime[temp_ses].ip = p.v[i].ip;
                PackagesTime[temp_ses].uplink.push_back(p.v[i].header->ts.tv_sec);
            }
        }
        map<Session, Packages>::iterator it;
        for(it = PackagesTime.begin(); it != PackagesTime.end(); it++)
        {
                cout << inet_ntoa(it->first.ip_src) << endl;
                cout << it->second.uplink.size() << endl;
                cout << it->second.downlink.size() << endl;
        }


       cout << "MAP SIZE " << PackagesTime.size();
}

