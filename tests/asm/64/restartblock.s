global _start

%include "defines.s"

handler:
	ret

restorer:
	mov rax, sigreturn
	syscall

_start:
	mov rax, 1
	shl rax, SIGALRM
	shr rax, 1
	push rax

	mov	rax, sigprocmask
	mov rdi, SIG_BLOCK
	mov	rsi, rsp
	mov rdx, 0
	mov	r10, 8
	syscall

	mov	rax, alarm
	mov	rdi, 1
	syscall

	push 0
	push 2
	mov	rax, nanosleep
	mov rdi, rsp
	syscall

	mov	rax, exit
	mov	rdi, 0
	syscall
