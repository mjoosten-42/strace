global _start

%include "defines.s"

_start:
	mov	rax, getpid
	syscall

	mov	rdi, rax
	mov rax, kill
	mov rsi, SIGTTIN
	syscall
	
	mov rax, exit
	mov rdi, 0
	syscall

