main: main.o Net_sniffer.o Statistic_analysis.o Packet.o Signature_analysis.o Session.o Working_classes.o
	g++ main.o Statistic_analysis.o Packet.o Signature_analysis.o Net_sniffer.o Session.o Working_classes.o -lpcap -o main 

main.o: main.cpp Net_sniffer.h Statistic_analysis.h Packet.h Signature_analysis.h
	g++ -c main.cpp -std=c++11

Statistic_analysis.o: Statistic_analysis.cpp Statistic_analysis.h 
	g++ -c Statistic_analysis.cpp -std=c++11

Packet.o: Packet.cpp Packet.h
	g++ -c Packet.cpp -std=c++11

SignatureAnalysis.o: Signature_analysis.c Signature_analysis.h
	g++ -c Signature_analysis.c -std=c++11     

Net_sniffer.o: Net_sniffer.cpp Net_sniffer.h
	g++ -c Net_sniffer.cpp -std=c++11
	
Session.o: Session.cpp Session.h
	g++ -c Session.cpp -std=c++11
	
Working_classes.o: Working_classes.cpp Working_classes.h
	g++ -c Working_classes.cpp

clean:
	rm *.o main
	sudo rm -rf result* 
