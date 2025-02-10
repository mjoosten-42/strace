global _start

%include "defines.s"

_start:
	push QWORD 800000000
	push QWORD 1
	mov	rax, nanosleep
	mov rdi, rsp
	syscall
	
	mov	rax, exit
	mov	rdi, 0
	syscall
