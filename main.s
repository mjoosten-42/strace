global _start

extern rt_sigprocmask

section	.data
filename:	db "Makefile"
str:		db "Hello World!"

section .bss

sigaction:	resb	64
statbuf:	resb	256
buf:		resb	1024

section .text

_start:
	mov		rax, 9
	mov		rdi, 0
	mov		rsi, 4096
	sub		rsi, 4096
	mov		rdx, 0x1 
	mov		r10, 0x02
	or		r10, 0x20
	mov		r8, -1
	mov		r11, 0
	syscall

	mov		rdi, rax
	mov		rax, 11
	mov		rsi, 4096
	syscall

	mov		rax, 60
	mov		rdi, 0
	syscall
