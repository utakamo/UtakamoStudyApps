all: ubus-sample02

CC = gcc
CFLAGS = -Wall
LDFLAGS = -lubus -lubox

DEPS = $(wildcard *.h)

SRC = $(wildcard *.c)

OBJ = $(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

datacheck: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f ubus-sample02 *.o datacheck
