main: build/ build/main.o build/Net_sniffer.o build/Statistic_analysis.o build/Packet.o build/Session.o build/Working_classes.o build/Signature_analysis.o build/Configuration.o build/tinystr.o build/tinyxml.o build/tinyxmlerror.o build/tinyxmlparser.o
	g++ build/main.o  build/Configuration.o build/Statistic_analysis.o build/Packet.o build/Net_sniffer.o build/Session.o build/Working_classes.o build/Signature_analysis.o build/tiny*.o -lpcap -o main 

build/main.o: src/main.cpp src/Net_sniffer.h src/Statistic_analysis.h src/Packet.h src/Signature_analysis.h
	g++-4.9 -c src/main.cpp  -std=c++11 -o build/main.o

build/Statistic_analysis.o: src/Statistic_analysis.cpp src/Statistic_analysis.h 
	g++ -c src/Statistic_analysis.cpp -std=c++11 -o build/Statistic_analysis.o

build/Packet.o: src/Packet.cpp src/Packet.h
	g++ -c src/Packet.cpp -std=c++11 -o build/Packet.o

build/Signature_analysis.o: src/Signature_analysis.cpp src/Signature_analysis.h
	g++-4.9 -c src/Signature_analysis.cpp -std=c++11 -o build/Signature_analysis.o

build/Net_sniffer.o: src/Net_sniffer.cpp src/Net_sniffer.h
	g++ -c src/Net_sniffer.cpp -std=c++11 -o build/Net_sniffer.o

build/Session.o: src/Session.cpp src/Session.h
	g++ -c src/Session.cpp -std=c++11 -o build/Session.o

build/Configuration.o: src/Configuration.cpp src/Configuration.h
	g++ -c -std=c++11 src/Configuration.cpp -o build/Configuration.o

build/Working_classes.o: src/Working_classes.cpp src/Working_classes.h
	g++ -c src/Working_classes.cpp -std=c++11 -o build/Working_classes.o

build/tinystr.o: lib/tinyxml/tinystr.cpp lib/tinyxml/tinystr.h
	g++ -c lib/tinyxml/tinystr.cpp -o build/tinystr.o

build/tinyxml.o: lib/tinyxml/tinyxml.cpp lib/tinyxml/tinyxml.h
	g++ -c lib/tinyxml/tinyxml.cpp -o build/tinyxml.o

build/tinyxmlerror.o: lib/tinyxml/tinyxmlerror.cpp lib/tinyxml/tinyxml.h
	g++ -c lib/tinyxml/tinyxmlerror.cpp -o build/tinyxmlerror.o

build/tinyxmlparser.o: lib/tinyxml/tinyxmlparser.cpp lib/tinyxml/tinyxml.h
	g++ -c lib/tinyxml/tinyxmlparser.cpp -o build/tinyxmlparser.o  

build/:
	mkdir -p build/

clean:
	rm -rf build

