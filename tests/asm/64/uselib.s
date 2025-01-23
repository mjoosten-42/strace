global _start

_start:
	mov	rax, 134	; uselib
	mov	rdi, 0
	syscall
	
	mov	rax, 60
	mov	rdi, 0
	syscall
