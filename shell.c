section .text
    global _start
_start:
    xor     rax, rax
    push    rax
    push    0x68732f2f
    push    0x6e69622f
    mov     rdi, rsp
    mov     rsi, rax
    mov     rax, 59
    syscall 
