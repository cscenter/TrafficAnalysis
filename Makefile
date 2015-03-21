all: start

start: main.o class_sniff.o StatisticAnalysis.o
	g++ main.o class_sniff.o StatisticAnalysis.o -lpcap -o start

main.o: main.c
	g++ -c main.c -lpcap     

class_sniff.o: class_sniff.c
	g++ -c class_sniff.c -lpcap 

StatisticAnalysis.o: StatisticAnalysis.cpp
	g++ -c StatisticAnalysis.cpp -lpcap 
    
clean:
	rm *.o start
