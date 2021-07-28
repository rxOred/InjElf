#include "util.h"
#include "elffile.h"
#include <fcntl.h>
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
    /* target file */
    char *filename = parse_args(argc, argv);
    Elf *target = elf_construct(filename);
    if(target == NULL){
        goto err;
    }

    if(target->InitFile(target) < 0){
        goto err1;
    }

    if(target->IsElf(target) == false){
        goto err1;
    }

    /* shellcode */
    char *shellcode_name = "shell";
    Elf *shellcode = elf_construct(shellcode_name);
    if(shellcode == NULL) {
        goto err1;
    }

    if(shellcode->InitFile(shellcode) < 0){
        goto err2;
    }

    if(shellcode->IsElf(shellcode) == false){
        goto err2;
    }

    shellcode->ParseHeaders(shellcode);

    target->ParseHeaders(target);
    struct text_padding_info = {
        .free_space = 
    }
err2:
    elf_destructor(shellcode);
err1:
    elf_destructor(target);
err:
    return -1;
}
