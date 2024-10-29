global _start

extern rt_sigprocmask

section	.data
filename:	db "Makefile"

section .bss

sigaction:	resb	64
statbuf:	resb	256

section .text

_start:
	mov		rax, 78
	mov		rdi, 0
	mov		rsi, 0
	mov		rdx, 0
	mov		r10, 0
	syscall
	
	mov		rax, 60
	mov		rdi, 1
	syscall
