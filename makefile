CC = gcc
CFLAGS = -lpcap -g -o
CFILES = detect.c

all: main

main: $(CFILES)
	$(CC) $(CFLAGS) nids $(CFILES)

clean:
	rm -f nids *.o