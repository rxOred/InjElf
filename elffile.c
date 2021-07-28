#include "elffile.h"
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>

static int elf_get_section_index_by_name(Elf *elf, const char   \
        *section_name)
{
    /* 
     * first we have to parse shstrtab
     */
    Elf64_Shdr *section = &elf->m_shdr[elf->m_ehdr->e_shstrndx];
    char *shstrtab = (char *)&elf->m_map[section->sh_offset];

    for(int i = 0; i < elf->m_ehdr->e_shnum; i++){
        if(strcmp(&shstrtab[elf->m_shdr[i].sh_name],            \
                    section_name) == 0){
            printf("%s section found\n", section_name);
            return i;
        }
    }

    return -1;
}

static struct text_padding_info *elf_find_free_space(Elf *elf)
{
    struct text_padding_info *pad_info = malloc(sizeof          \
            (struct text_padding_info));
    if(pad_info == NULL){
        printf("memory allocation failed\n");
        goto err;
    }

    memset(pad_info, 0, sizeof(struct text_padding_info));

    for(int i = 0; i < elf->m_ehdr->e_phnum; i++){
        if(elf->m_phdr[i].p_type == PT_LOAD && elf->m_phdr      \
                [i].p_flags == (PF_R | PF_X)){
            printf("text segment found\n");
            pad_info->text_filesize = elf->m_phdr[i].p_filesz;
            pad_info->text_memsize = elf->m_phdr[i].p_memsz;
            pad_info->text_start = elf->m_phdr[i].p_offset;
            pad_info->text_end = pad_info->text_start +         \
                elf->m_phdr[i].p_filesz;

        } else if (elf->m_phdr[i].p_type == PT_LOAD &&          \
                (elf->m_phdr[i].p_offset - pad_info->text_end)
                < pad_info->freespace) {
            printf("segment found with a gap of %d\n",          \
                    pad_info->freespace);
            pad_info->freespace = elf->m_phdr[i].p_offset -     \
                pad_info->text_end;
            printf("final gap size %d\n", pad_info->freespace);
        } else {
            fprintf(stderr, "failed to find a code cave\n");
            goto err;
        }
    }

err:
    return pad_info;
}

static void elf_parse_headers(Elf *elf)
{
    elf->m_ehdr = (Elf64_Ehdr *) elf->m_map;
    elf->m_phdr = (Elf64_Phdr *) &elf->m_map[elf->m_ehdr->      \
        e_phoff];
    elf->m_shdr = (Elf64_Shdr *) &elf->m_map[elf->m_ehdr->      \
        e_shoff];
}

static bool elf_is_elf(Elf *elf)
{
    if(elf->m_map == NULL){
        fprintf(stderr, "file not mapped\n");
        goto err;
    }

    if(elf->m_map[0] != 0x7f || elf->m_map[1] != 'E' ||         \
            elf->m_map[2] != 'L' || elf->m_map[3] != 'F'){
        fprintf(stderr, "not an elf binary\n");
        goto err;
    }

    return true;

err:
    return false;
}

static int elf_destroy_file(Elf *this)
{
    if(this->m_map != NULL){
        if(munmap(this->m_map, this->m_size) < 0){
            fprintf(stderr, "memory unmap failed\n");
            goto err;
        }
        this->m_map = NULL;
        return 0;
    }
err:
    return -1;
}

static int elf_init_file(Elf *this)
{
    if(this->m_filename == NULL){
        fprintf(stderr, "filename not specified\n");
        goto err;
    }

    int fd = open(this->m_filename, O_RDWR);
    if(fd < 0){
        fprintf(stderr, "file open error");
        goto err;
    }

    struct stat st;
    if(fstat(fd, &st) < 0){
        fprintf(stderr, "fstat failed\n");
        goto err1;
    }

    this->m_size = st.st_size;
    this->m_map = mmap(NULL, this->m_size, PROT_READ | PROT_WRITE, \
            MAP_PRIVATE, fd, 0);
    if(this->m_map == MAP_FAILED){
        fprintf(stderr, "memory map failed");
        goto err1;
    }

    close(fd);
    return 0;

err1:
    close(fd);
err:
    return -1;
}

Elf *elf_construct(char *filename)
{
    struct Elf *elf = malloc(sizeof(Elf));
    if(elf == NULL){
        fprintf(stderr, "memory allocation failed\n");
        goto err;
    }

    elf->m_filename = filename;
    elf->m_size = 0;
    elf->m_map = NULL;
    elf->m_ehdr = NULL;
    elf->m_phdr = NULL;
    elf->m_shdr = NULL;
    elf->InitFile = elf_init_file;
    elf->DestroyFile = elf_destroy_file;
    elf->IsElf = elf_is_elf;
    elf->ParseHeaders = elf_parse_headers;
    elf->FindFreeSpace = elf_find_free_space;
    elf->FindSectionIndexByName = elf_get_section_index_by_name;
err:
    return elf;
}
