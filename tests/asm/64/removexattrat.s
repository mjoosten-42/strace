global _start

%include "defines.s"

_start:
	mov	rax, removexattrat
	mov	rdi, 0
	syscall
	
	mov	rax, exit
	mov	rdi, 0
	syscall
