BITS 32

global _start

_start:
    mov eax, [esp]           ; argc

    cmp eax, 2
    jl _ret
    
    lea eax, [esp + 4]      ; argv
    mov ebx, [esp + 8]		; argv[1]
    lea ecx, [esp + 8]		; argv + 1
    mov edx, 0x0			; envp
    mov eax, 11				; execve
    int	0x80

_ret:
    mov eax, 1              ; exit
    xor ebx, ebx 
    int 0x80

.loop:
	jmp .loop

