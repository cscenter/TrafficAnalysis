main: main.o class_sniff.o StatisticAnalysis.o SignatureAnalisator.o 
	g++ main.o class_sniff.o StatisticAnalysis.o SignatureAnalisator.o -lpcap -o main 

main.o: main.c class_sniff.h StatisticAnalysis.h
	g++ -c main.c 
 
class_sniff.o: class_sniff.c class_sniff.h
	g++ -c class_sniff.c 

StatisticAnalysis.o: StatisticAnalysis.cpp StatisticAnalysis.h 
	g++ -c StatisticAnalysis.cpp -std=c++11
 
SignatureAnalisator.o: SignatureAnalisator.c SignatureAnalisator.h
	g++ -c SignatureAnalisator.c 
    
clean:
	rm *.o main
