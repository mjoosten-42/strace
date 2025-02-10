global _start

%include "defines.s"

_start:
	mov	rax, exit
	mov	rdi, 1
	syscall
