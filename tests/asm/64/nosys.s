global _start

_start:
	mov	rax, 500
	mov rdi, 0
	mov rsi, -1
	mov rdx, 10000
	mov r8, 0xFFFFFFFF
	mov r9, 0x8FFFFFFF
	syscall
	
	mov	rax, 60
	mov	rdi, 0
	syscall
