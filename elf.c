#include "elf.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*
 * uninitialize
 */
int elf_destroy_file(Elf *this)
{
    if(this->m_map != NULL){
        if(munmap(this->m_map, this->m_size) < 0){
            fprintf(stderr, "memory unmap failed\n");
            goto err;
        }
        this->m_map = NULL;
    }
err:
    return -1;
}

/*
 * initialization
 */
int elf_init_file(Elf *this)
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
    this->m_map = mmap(NULL, this->m_size, PROT_READ |
            PROT_WRITE, MAP_PRIVATE, fd, 0);
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

/*
 * constructor
 */
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

err:
    return NULL;
}


