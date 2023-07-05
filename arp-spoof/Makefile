LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h main.h main.cpp

util.o : util.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o util.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -I . -lpthread

clean:
	rm -f *.o

fclean: clean
	rm -f arp-spoof


re: fclean all
