global _start

%include "defines.s"

_start:
    int3

	mov rax, exit
	mov rsi, 0
	syscall

