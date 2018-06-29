DEFINES += -DHTTP_LOG_LEVEL=9
#DEFINES += -DHTTP_SERVER
#DEFINES += -DHTTP_CLIENT

CFLAGS = -std=c99 -g -Wall $(DEFINES)
LDFLAGS = -lwolfssl

SOURCES = http.c misc.c
HEADERS = http.h misc.h

CC = gcc

all: test

# all tests
test: client_test server_test others_test

# HTTP client test
client_test: Makefile $(SOURCES) $(HEADERS) test/client_test.c
	$(CC) -o test/client $(CFLAGS) -DHTTP_CLIENT -I. $(SOURCES) test/client_test.c $(LDFLAGS)

# HTTP server test
server_test: Makefile $(SOURCES) $(HEADERS) test/server_test.c
	$(CC) -o test/server $(CFLAGS) -DHTTP_SERVER -I. $(SOURCES) test/server_test.c $(LDFLAGS)

# HTTP others test
others_test: Makefile $(SOURCES) $(HEADERS) test/others_test.c
	$(CC) -o test/others $(CFLAGS) -I. $(SOURCES) test/others_test.c $(LDFLAGS)

.PHONY: clean
clean:
	rm -f test/client
	rm -f test/server
	rm -f test/others
