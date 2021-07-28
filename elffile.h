#ifndef ELFFILE_H
#define ELFFILE_H

#include <bits/stdint-uintn.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

struct text_padding_info {
    Elf64_Xword text_filesize, text_memsize;
    Elf64_Phdr *text_phdr;
    Elf64_Off text_start, text_end;
    int freespace;
};

/*
 * Elf Class
 */
struct Elf {
    char *m_filename;
    int m_size;
    uint8_t *m_map;
    Elf64_Ehdr *m_ehdr;
    Elf64_Shdr *m_shdr;
    Elf64_Phdr *m_phdr;

    int (*InitFile) (struct Elf *self);
    bool (*IsElf) (struct Elf *self);
    void (*ParseHeaders) (struct Elf *self);

    struct text_padding_info* (*FindFreeSpace) (struct  \
            Elf *self);

    int (*FindSectionIndexByName) (struct Elf *self,    \
            const char *section_name);
};
typedef struct Elf Elf;

Elf *elf_constructor(char *filename);
int elf_destructor(Elf *self);

#endif /* ELFFILE_H */
