main: main.o Net_sniffer.o Statistic_analysis.o Packet.o Session.o Working_classes.o Signature_analysis.o Configuration.o
	g++ main.o  Configuration.o Statistic_analysis.o Packet.o Net_sniffer.o Session.o Working_classes.o Signature_analysis.o tiny*.o -lpcap -o main 
	
main.o: main.cpp Net_sniffer.h Statistic_analysis.h Packet.h Signature_analysis.h
	g++-4.9 -c main.cpp  -std=c++11 
	
Statistic_analysis.o: Statistic_analysis.cpp Statistic_analysis.h 
	g++ -c Statistic_analysis.cpp -std=c++11
	
Packet.o: Packet.cpp Packet.h
	g++ -c Packet.cpp -std=c++11
	
Signature_analysis.o: Signature_analysis.cpp Signature_analysis.h
	g++-4.9 -c Signature_analysis.cpp -std=c++11
	
Net_sniffer.o: Net_sniffer.cpp Net_sniffer.h
	g++ -c Net_sniffer.cpp -std=c++11
		
Session.o: Session.cpp Session.h
	g++ -c Session.cpp -std=c++11
	
Configuration.o: Configuration.cpp Configuration.h
	g++ -c -std=c++11 Configuration.cpp tinyxml/tinyxml.cpp tinyxml/tinystr.cpp tinyxml/tinyxmlerror.cpp tinyxml/tinyxmlparser.cpp
	
Working_classes.o: Working_classes.cpp Working_classes.h
	g++ -c Working_classes.cpp -std=c++11
	
clean:
	rm *.o main
	sudo rm -rf result* 
	sudo rm -rf *.txt
