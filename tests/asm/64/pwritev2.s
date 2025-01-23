global _start

_start:
	mov rax, 547	; pwritev2
	mov rdi, 0
	syscall

	mov rax, 60
	mov rdi, 0
	syscall
