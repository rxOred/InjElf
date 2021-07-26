#include <bits/stdint-uintn.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

struct Elf{
    char *m_filename;
    int m_size;
    uint8_t *m_map;
    Elf64_Ehdr *m_ehdr;
    Elf64_Shdr *m_shdr;
    Elf64_Phdr *m_phdr;

    int (*InitFile) (struct Elf *this);
    int (*DestroyFile) (struct Elf *this);
    bool (*IsElf) (struct Elf *this);
    void (*ParseHeaders) (struct Elf *this);
};
typedef struct Elf Elf;

Elf *elf_construct(char *filename);
