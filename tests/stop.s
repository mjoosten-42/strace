global _start

_start:
	mov	rax, 39		; getpid
	syscall

	mov	rdi, rax
	mov rax, 62		; kill
	mov rsi, 19		; SIGSTOP
	syscall

