global _start

%include "defines.s"

_start:
	mov	rcx, rsp
	sub	rsp, 40
	
	mov	QWORD [rcx + 0],	SIG_IGN
	mov	QWORD [rcx + 8],	0 ; flags
	mov	QWORD [rcx + 16],	SIGINT
	mov	QWORD [rcx + 24],	0

	mov	rax, sigaction
	mov	rdi, SIGINT
	mov	rsi, rcx
	mov	rdx, 0
	mov r10, 8
	syscall

	mov rax, getpid
	syscall

	mov rdi, rax
	mov	rax, kill
	mov rsi, SIGINT
	syscall

	mov	rax, exit
	mov	rdi, 0
	syscall
