LDLIBS=-lpcap

all: tcp-block

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

mac.o : mac.h mac.cpp

main.o: main.h main.cpp

tcphdr.o: iphdr.h tcphdr.h tcphdr.cpp

util.o : util.cpp main.h

send_packet.o : send_packet.cpp

tcp-block: util.o main.o ethhdr.o mac.o tcphdr.o  iphdr.o ip.o send_packet.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -I . -lpthread

clean:
	rm -f *.o

fclean: clean
	rm -f tcp-block

re: fclean all
