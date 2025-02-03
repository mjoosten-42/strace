global _start

_start:
	mov	rax, 400
	mov rdi, 0
	mov rsi, 1
	mov rdx, 2
	mov r10, 3
	mov r8,  4
	mov r9,  5
	syscall
	
	mov	rax, 60
	mov	rdi, 0
	syscall
