global _start

%include "defines.s"

_start:
	mov rax, landlock_add_rule
	mov rdi, -1
	mov rsi, 1
	mov rdx, 0
	syscall

	mov rax, exit
	mov rdi, 0
	syscall
