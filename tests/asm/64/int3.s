global _start

_start:
    int3

	mov rax, 60		; exit
	mov rsi, 0
	syscall

