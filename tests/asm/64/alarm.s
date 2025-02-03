global _start

%define SIGALRM 14
%define sigaction 13
%define SA_RESTORER 0x04000000

handler:
	ret

restorer:
	mov rax, 15
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

	mov	rax, 37		; alarm
	mov	rdi, 1
	syscall

	mov	rax, 34		; pause
	syscall

	mov	rax, 60		; exit
	mov	rdi, 0
	syscall
