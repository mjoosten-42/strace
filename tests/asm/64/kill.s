global _start

%include "defines.s"

_start:
	mov	rax, getpid
	syscall

	mov	rdi, rax
	mov rax, kill
	mov rsi, SIGKILL
	syscall

