#include "util.h"
#include "main.h"
#include <stdio.h>
#include <string.h>

void parse_args(Elf *elf, int argc, char *argv[])
{
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-f") == 0){
            elf->m_filename = strdup(argv[i + 1]);
        } else if(strcmp(argv[i], "-p") == 0){
            sscanf(argv[i + 1], "%d", &elf->m_port_number);
        }
    }
}

int main(int argc, char *argv[])
{
    Elf elf;
    parse_args(&elf, argc, argv);
}
