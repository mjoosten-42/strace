global _start

%include "defines.s"

_start:
	mov	rax, uselib
	mov	rdi, 0
	syscall
	
	mov	rax, exit
	mov	rdi, 0
	syscall
