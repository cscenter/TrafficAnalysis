main: Net_sniffer.o Statistic_analysis.o Class_parse_packet.o SignatureAnalisator.o main.o
	g++ Net_sniffer.o Statistic_analysis.o Class_parse_packet.o SignatureAnalisator.o  main.o -lpcap -o main 

Net_sniffer.o: Net_sniffer.c Net_sniffer.h
	g++ -c Net_sniffer.c

Statistic_analysis.o: Statistic_analysis.cpp Statistic_analysis.h 
	g++ -c Statistic_analysis.cpp -std=c++11

Class_parse_packet.o: Class_parse_packet.cpp Class_parse_packet.h
	g++ -c Class_parse_packet.cpp
 
SignatureAnalisator.o: SignatureAnalisator.c SignatureAnalisator.h
	g++ -c SignatureAnalisator.c    
 
main.o: main.c Net_sniffer.h Statistic_analysis.h Class_parse_packet.h SignatureAnalisator.h
	g++ -c main.c 

clean:
	rm *.o main
