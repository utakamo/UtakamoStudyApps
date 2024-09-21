all: uci-sample08

CC = gcc
CFLAGS = -Wall
LDFLAGS = -luci -lubox

DEPS = $(wildcard *.h)

SRC = $(wildcard *.c)

OBJ = $(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

datacheck: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f uci-sample08 *.o datacheck
