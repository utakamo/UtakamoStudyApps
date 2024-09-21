all: ubus-sample01

CC = gcc
CFLAGS = -Wall
LDFLAGS = -luci -lubus -lubox

DEPS = $(wildcard *.h)

SRC = $(wildcard *.c)

OBJ = $(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

datacheck: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f ubus-sample01 *.o datacheck
