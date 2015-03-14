#define PCAP_OPENFLAG_PROMISCUOUS   1
#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 
#include <time.h>
#include <iostream>
#include <vector>

using namespace std;

vector<int> v;

FILE *  fp;

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* 
	packet) 
{ 
        static int begin = 0;
        if (begin == 0) begin = pkthdr->ts.tv_sec;
        static int pred = -1;
        if (pkthdr->ts.tv_sec > pred + 1 && pred != -1 && pred != 0)
        {
            int i;
            for ( i = 0; i < pkthdr->ts.tv_sec - pred - 1; i++)
            {
                v.push_back(0);
            }
        }   
        if (pred == (int)(pkthdr->ts.tv_sec)) v[v.size() - 1]++;
        else
        {
             pred = pkthdr->ts.tv_sec;
             v.push_back(1);
        }        

}

void write()
{ 
             fp = fopen("new.txt", "w"); 
             if (fp == NULL) printf("File wasn't opened or created");
             int i;
             printf("I am hear \n"); 
             for (i = 0; i < v.size(); i++)
             {
                  fprintf(fp, "%d %d\n", i, v[i]);
             }
             fclose(fp);
}

/*
void daemonize()
{
	signal(SIGTERM, signal_handler);
} */

int main(int argc,char **argv) 
{ 
	int i;
	char errbuf[PCAP_ERRBUF_SIZE]; 
        pcap_t *adhandle;   

	if(argc != 2){
		fprintf(stdout, "Usage: %s \"expression\"\n" 
			,argv[0]);
		return 0;
	} 

	/* Получение имени устройства */
	char* dev = argv[1];	
	
	if(dev == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	} 
	
     	adhandle = pcap_open_offline(dev, errbuf);  
        if (adhandle == NULL) 
        { 
                printf("Couldn't open pcap file %s: %s\n", dev, errbuf); 
                return(2); 
        } 
   	 
    	pcap_loop(adhandle, 0, my_callback, NULL);
        printf("%s", pcap_geterr(adhandle));  
        pcap_close(adhandle);
        write();
	return 0;
        
}

