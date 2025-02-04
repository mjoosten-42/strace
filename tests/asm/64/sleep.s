global _start

_start:
	push QWORD 0
	push QWORD 1
	mov	rax, 35		; nanosleep
	mov rdi, rsp
	syscall
	
	mov	rax, 60
	mov	rdi, 0
	syscall
