global _start

extern rt_sigprocmask

section .bss

sigaction:	resb	64

section .text

_start:
	mov 	rax, 270
	mov		edi, 0
	mov		rsi, 0
	mov		rdx, 0
	mov		r10, 0
	syscall

	mov		rax, 60
	mov		rdi, 1
	syscall
