#include <bits/stdint-uintn.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>

struct Elf{
    char *m_filename;
    FILE *m_elf;
    uint8_t *m_map;
    uint32_t m_port_number;
    Elf64_Ehdr *m_ehdr;
    Elf64_Shdr *m_shdr;
    Elf64_Phdr *m_phdr;

    int (*InitFile)(struct Elf *this);
};

typedef struct Elf Elf;
