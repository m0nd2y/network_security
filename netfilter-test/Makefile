all: netfilter-test

CC=g++

CFLAGS=-c -Wall

SOURCES = netfilter-test.c

OBJECTS = $(SOURCES:.c=.o)

netfilter-test: $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ -lnetfilter_queue

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o

fclean: clean
	rm -f netfilter-test

re: fclean all
