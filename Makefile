all: snif.o
	g++ snif.o -lpcap -o snif
    
snif.o: snif.c
	g++ -c snif.c
    
clean:
	rm *.o snif
