global _start

buf:
	.zero 1024

_start:
	mov	rax, 37		; alarm
	mov	rdi, 1
	syscall

	mov	rax, 0		; read
	mov	rdi, 0
	mov	rsi, buf
	mov	rdx, 1024
	syscall


