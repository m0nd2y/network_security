LDLIBS=-lpcap

all: airodump

main.o: main.h main.cpp

mac.o : mac.h mac.cpp

airodump: mac.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -I .

clean:
	rm -f *.o

fclean: clean
	rm -f airodump

re: fclean all

