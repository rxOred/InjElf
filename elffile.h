#ifndef ELFFILE_H
#define ELFFILE_H

#include <bits/stdint-uintn.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

/*
 * Elf Class
 * Holds structures and other information related to 
 * Elf binaries in general. Base class for Shellcode
 * & Target classes
 */
struct Elf {
    const char *m_filename;
    int m_size;
    void *m_map;
    Elf64_Ehdr *m_ehdr;
    Elf64_Shdr *m_shdr;
    Elf64_Phdr *m_phdr;

    int (*InitFile) (struct Elf *self);
    bool (*IsElf) (struct Elf *self);
    void (*ParseHeaders) (struct Elf *self);
    int (*FindSectionIndexByName) (struct Elf *self,    \
            const char *section_name);
};
typedef struct Elf Elf;

Elf *ElfConstructor(const char *filename);
void ElfDestructor(Elf *self);


/*
 * Shellcode Class - Shellcode elf binary
 * Derived from its base, Class Elf
 * shellcode information
 */
struct Shellcode {
    Elf *m_elf;
    void *m_shellcode;
    int m_shellcode_size;

    int (*ShellcodeExtractText) (struct Shellcode *self \
            , int index);
    int (*PatchRetAddress) (struct Shellcode *self,     \
            Elf64_Addr);
};
typedef struct Shellcode Shellcode;

Shellcode *ShellcodeConstructor(const char *filename);
void ShellcodeDestructor(Shellcode *self);


/*
 * Target Class - depicts Target elf binary
 * Derived from its base, Class Elf
 */
struct Target {
    Elf *m_elf;
    Elf64_Xword text_filesize;
    Elf64_Off text_end;
    Elf64_Addr parasite_addr;
    int available_freespace;

    int (*TargetFindFreeSpace) (struct Target *self,    \
        int parasite_size);
    void (*TargetAdjustSections) (struct Target *self,  \
        int parasite_size);
    void (*TargetInsertShellcode) (struct Target *self, \
        Shellcode *shellcode);
    int (*TargetSaveFile) (struct Target *self);
};
typedef struct Target Target;

Target *TargetConstructor(const char * filename);
void TargetDestructor(Target *self);

#endif /* ELFFILE_H */
