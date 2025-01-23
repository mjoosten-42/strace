global _start

_start:
	mov	rax, 39		; getpid
	syscall

	mov	rdi, rax
	mov rax, 62		; kill
	mov rsi, 17		; SIGCHLD (ignored)
	syscall

	mov rax, 60		; exit
	mov	rdi, 0
	syscall
