global _start

_start:
	mov rax, 448	; mrelease
	mov rdi, -1
	mov rsi, 0
	syscall

	mov rax, 60
	mov rdi, 0
	syscall
