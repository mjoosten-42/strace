global _start

%include "defines.s"

_start:
	mov rax, process_mrelease
	mov rdi, -1
	mov rsi, 0
	syscall

	mov rax, exit
	mov rdi, 0
	syscall
