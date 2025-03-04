global _start

%include "defines.s"

_start:
	mov	rax, alarm
	mov	rdi, 1
	syscall

	mov rdi, 2000
	call fib

	mov	rax, exit
	mov	rdi, 0
	syscall

fib:
	mov rax, rdi
	cmp rdi, 1		; if (n != 2)
	jle .end

	dec	rdi
	push rdi
	call fib
	mov rcx, rax
	pop rdi
	dec rdi
	call fib

	add rax, rcx
.end:
	ret

