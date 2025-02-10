global _start

%include "defines.s"

_start:
	mov rax, pwrite2
	mov rdi, 0
	syscall

	mov rax, exit
	mov rdi, 0
	syscall
