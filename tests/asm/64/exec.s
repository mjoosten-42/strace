global _start

_start:
    mov r8, [rsp]           ; argc
    lea r9, [rsp + 8]       ; argv

    cmp r8, 2
    jl _ret
    
    mov rax, 59             ; execve
    mov rdi, [r9 + 8]       ; argv[1]
    lea rsi, [r9 + 8]       ; argv + 1
    lea rdx, [r9 + 8 * r8]	; envp
    syscall

_ret:
    mov rax, 60             ; exit
    xor rdi, rdi 
    syscall

