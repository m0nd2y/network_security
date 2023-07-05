CC=g++
CFLAGS =-c -Wall
LDLIBS = -pthread

SOURCES_SERVER = echo-server.cpp
SOURCES_CLIENT = echo-client.cpp

OBJECTS_SERVER = $(SOURCES_SERVER:.c=.o)
OBJECTS_CLIENT = $(SOURCES_CLIENT:.c=.o)

all: echo-server echo-client

echo-server : $(OBJECTS_SERVER)
	$(CC) $(OBJECTS_SERVER) -o $@ $(LDLIBS)

echo-client : $(OBJECTS_CLIENT)
	$(CC) $(OBJECTS_CLIENT) -o $@ $(LDLIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -f  *.o

fclean : clean
	rm -f echo-server echo-client

re : fclean all