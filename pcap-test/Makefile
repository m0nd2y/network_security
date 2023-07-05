NAME	=	pcap-test
RM		=	rm -f
CC		=	gcc
CFLAGS	=	-Wall -Wextra -Werror
SRCS	=	pcap-test.c

OBJS	=	$(SRCS:.c=.o)


$(NAME) : $(OBJS)
		$(CC) -o $(NAME) $(CFLAGS) $(OBJS) -lpcap

all	: $(NAME)

clean :
	$(RM) $(OBJS)

fclean	: clean
	$(RM) $(NAME)

re : fclean all

.PHONY : all clean fclean re