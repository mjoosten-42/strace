global _start

_start:
	mov rax, 12		; brk
	mov rdi, 0
	syscall

	mov rax, 60
	mov rdi, 0
	syscall
