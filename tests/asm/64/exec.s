global _start

%include "defines.s"

_start:
    mov r8, [rsp]           ; argc
    lea r9, [rsp + 8]       ; argv

    cmp r8, 2
    jl _ret
    
    mov rax, execve
    mov rdi, [r9 + 8]       ; argv[1]
    lea rsi, [r9 + 8]       ; argv + 1
    lea rdx, [r9 + 8 * r8]	; envp
    syscall

_ret:
    mov rax, exit
	mov rdi, 0
    syscall

