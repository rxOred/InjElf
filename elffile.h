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
    int (*DestroyFile) (struct Elf *self);
    bool (*IsElf) (struct Elf *self);
    void (*ParseHeaders) (struct Elf *self);

    Elf64_Phdr* (*FindFreeSpace) (struct Elf *self,     \
            struct padding_info *pad_info);

};
typedef struct Elf Elf;

Elf *elf_construct(char *filename);

#endif /* ELFFILE_H */
