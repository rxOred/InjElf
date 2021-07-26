#include "util.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*
 * parse command line arguments
 */
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
    char *filename = parse_args(argc, argv);
}
