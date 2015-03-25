all: start

start: main.o class_sniff.o StatisticAnalysis.o SignatureAnalisator.o
	g++ main.o class_sniff.o StatisticAnalysis.o -lpcap -o start

main.o: main.c
	g++ -c main.c  class_sniff.c class_sniff.h  

class_sniff.o: class_sniff.c
	g++ -c class_sniff.c class_sniff.h main.c

StatisticAnalysis.o: StatisticAnalysis.cpp
	g++ -c StatisticAnalysis.cpp StatisticAnalysis.h

SignatureAnalisator.o: SignatureAnalisator.c
	g++ -c SignatureAnalisator.c SignatureAnalisator.h main.c
    
clean:
	rm *.o start
