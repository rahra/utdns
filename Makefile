CC = gcc
CFLAGS = -Wall -Wextra -g

utdns: utdns.o smlog.o

smlog.o: smlog.c

utdns.o: utdns.c

clean:
	rm -f *.o utdns

.PHONY: clean

