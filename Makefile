CC=gcc
CFLAGS=-O2 -Wall -Wextra -std=c99 -Wno-unused-parameter -fPIC -g
OBJS=main.o fixture.o bootstrap.o

all: meta

test: meta
	./meta < boot.lop

clean:
	rm *.o meta

.PHONY: all clean test

meta: $(OBJS)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<
