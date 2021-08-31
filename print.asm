section .text
    global _start

_start:         push    rdi
                push    rsi
                jmp     string

print:          mov     rsi,    QWORD[rsp]
                mov     rax,    0x1
                mov     rdx,    20
                mov     rdi,    1
                syscall 

                pop     rax
                pop     rsi
                pop     rdi
                mov     rax,    0x991234
                jmp     rax

string:         call    print
                db      "shellcodes gobrrrr", 0xa, 0x0
