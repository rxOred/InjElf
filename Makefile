CC=gcc
CFLAGS=-g -Wall
OBJS=objs/elffile.o objs/main.o
BIN=injector

all:$(BIN)
	nasm -f elf64 -o print.o print.asm
	ld -m elf_x86_64 -o print print.o
	gcc $(CFLAGS) -static target.c -o target

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN)

objs/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf objs/* injector target 
