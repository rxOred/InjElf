section .text
    global _start
_start:
    xor     rax, rax
    mov     rbx, '/bin/sh'
    push    rbx
    mov     rdi, rsp
    mov     rsi, rax
    mov     rax, 59
    syscall 
