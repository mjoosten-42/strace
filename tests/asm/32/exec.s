BITS 32

global _start

_start:
    mov ebx, [esp]				; argc

    cmp ebx, 2
    jl _ret
    
    lea eax, [esp + 4]      	; argv
    lea edx, [eax + 4 * ebx]	; envp
    mov ebx, [esp + 8]			; argv[1]
    lea ecx, [esp + 8]			; argv + 1
    mov eax, 11					; execve
    int	0x80

_ret:
    mov eax, 1           		; exit
	mov ebx, 0 
    int 0x80

.loop:
	jmp .loop

