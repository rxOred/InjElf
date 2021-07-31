CC=gcc
CFLAGS=-g -Wall
OBJS=objs/elffile.o objs/main.o
BIN=injector

all:$(BIN)

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN)

objs/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf objs/* injector
