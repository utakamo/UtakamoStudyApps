all: luci-app-sample03

CC = gcc
CFLAGS = -Wall
LDFLAGS = -luci -lubus -lubox

DEPS = $(wildcard *.h)

SRC = $(wildcard *.c)

OBJ = $(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

luci-app-sample03: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

datacheck: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f luci-app-sample03 *.o datacheck
