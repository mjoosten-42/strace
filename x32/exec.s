BITS 32

global _start

_start:
    mov eax, [esp]           ; argc

    cmp eax, 2
    jl _ret
    
    lea eax, [esp + 4]      ; argv
    mov ebx, [eax + 4]       ; argv[1]
    mov ecx, [eax + 4]    ; argv + 1
    mov edx, 0x0          ; envp
    mov eax, 11             ; execve
    syscall

_ret:
    mov eax, 1              ; exit
    xor ebx, ebx 
    syscall

