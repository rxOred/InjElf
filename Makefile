CC=gcc
CFLAGS=-g -Wall
OBJS=objs/elffile.o objs/main.o
BIN=injector

all:$(BIN)
	nasm -f elf64 -o shellcode.o shellcode.asm
	ld -m elf_x86_64 -o shellcode shellcode.o
	gcc -static target.c -o target

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(BIN)

objs/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf objs/* injector
