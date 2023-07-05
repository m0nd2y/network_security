LDLIBS=-lpcap

all: deauth-attack

main.o: main.h main.cpp

util.o: util.cpp

dot11hdr.o : dot11hdr.cpp dot11hdr.h

mac.o: mac.cpp

deauth-attack: dot11hdr.o util.o main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -I .

clean:
	rm -f *.o

fclean: clean
	rm -f deauth-attack

re: fclean all

