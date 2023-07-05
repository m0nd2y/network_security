all: 1m-block

CC=g++

CFLAGS=-c -Wall

SOURCES = 1m-block.c

OBJECTS = $(SOURCES:.c=.o)

1m-block: $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ -lnetfilter_queue

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o

fclean: clean
	rm -f 1m-block

re: fclean all
