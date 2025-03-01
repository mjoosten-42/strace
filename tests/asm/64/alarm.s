global _start

%include "defines.s"

handler:
	ret

restorer:
	mov rax, sigreturn
	syscall

_start:
	mov	rcx, rsp
	sub	rsp, 40

	lea	rax, [handler]
	mov	QWORD [rcx + 0],	rax
	
	lea rax, [restorer]
	mov	QWORD [rcx + 8],	SA_RESTORER
	mov	QWORD [rcx + 16],	rax
	mov	QWORD [rcx + 24],	0

	mov	rax, sigaction
	mov	rdi, SIGALRM
	mov	rsi, rcx
	mov	rdx, 0
	mov r10, 8
	syscall

	mov	rax, alarm
	mov	rdi, 1
	syscall

	mov	rax, pause
	syscall

	mov	rax, exit
	mov	rdi, 0
	syscall
