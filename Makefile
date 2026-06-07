CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS    = -lssl -lcrypto -lsodium
TARGET  = server
SRC     = server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

cert:
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
	-days 365 -nodes -subj "/CN=secserver"

clean:
	rm -f $(TARGET)

.PHONY: all cert clean
