DEFINES += -DHTTP_LOG_LEVEL=9
DEFINES += -DHTTP_SERVER
DEFINES += -DHTTP_CLIENT

CFLAGS = -std=c99 -g -Wall $(DEFINES)
LDFLAGS = -lwolfssl

SOURCES = http.c misc.c main.c
HEADERS = http.h misc.h

CC = gcc

all: test

test: Makefile $(SOURCES) $(HEADERS)
	$(CC) -o test $(CFLAGS) $(SOURCES) $(LDFLAGS)

.PHONY: clean
clean:
	rm test
