global _start

extern rt_sigprocmask

section	.data
filename:	db "Makefile"

section .bss

sigaction:	resb	64
statbuf:	resb	256

section .text

_start:
	mov 	rax, 4
	mov		rdi, filename
	mov		rsi, statbuf
	syscall

	mov		rax, 60
	mov		rdi, 1
	syscall
