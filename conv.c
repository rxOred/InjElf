#include <stdio.h>

int main(void)
{
    unsigned long long address = 0x1fff8ffff9ffffff;
    char buf[16];
    int addr[16];

    sprintf(buf, "%lx", address);
    for (int i = 0; i < 16; i++){
        if(buf[i] >= 0x61 && buf[i] <= 0x66){
            addr[i] = buf[i] - 87;
            printf("a-h , %x %d\n", addr[i], addr[i]);
        }

        else if (buf[i] >= 0x30 && buf[i] <= 0x39){
            addr[i] = buf[i] - 48;
            printf("1-9 , %x %d\n", addr[i], addr[i]);
        }
        else 
            goto err;
    }

    for (int i = 0; i < 16; i++){
        printf("%x", addr[i]);
    }
err:

#ifdef DEBUG
    printf("not a valid memory address\n");
#endif

    return -1;
}
