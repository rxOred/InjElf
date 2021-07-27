;simple hello world nasm program.
;this is useless for a malware
;write a reverse shell to be more practical

section .data
    msg     db  "hacked", 0xa, 0x0

section .text
    global _start

_start:
    mov     rax, 1
    mov     rdi, 1
    mov     rsi, msg
    mov     rdx, 8
    syscall

    mov     rax, 60
    syscall
