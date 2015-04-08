main: main.o Net_sniffer.o Statistic_analysis.o Parse_packet.o Signature_analysis.o 
	g++ main.o Net_sniffer.o Statistic_analysis.o Parse_packet.o Signature_analysis.o -lpcap -o main 

main.o: main.cpp Net_sniffer.h Statistic_analysis.h Parse_packet.h Signature_analysis.h
	g++ -c main.cpp 

Net_sniffer.o: Net_sniffer.cpp Net_sniffer.h
	g++ -c Net_sniffer.cpp

Statistic_analysis.o: Statistic_analysis.cpp Statistic_analysis.h 
	g++ -c Statistic_analysis.cpp -std=c++11

Class_parse_packet.o: Parse_packet.cpp Parse_packet.h
	g++ -c Parse_packet.cpp

SignatureAnalisator.o: Signature_analysis.c Signature_analysis.h
	g++ -c Signature_analysis.c    

clean:
	rm *.o main
