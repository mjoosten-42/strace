global _start

_start:
	mov rcx, rsp
	sub rsp, 40
	mov	DWORD [rcx + 0], 0
	mov WORD [rcx + 4], 1
	mov WORD [rcx + 6], 0
	mov	rax, 7		; poll
	mov	rdi, rcx
	mov	rsi, 1
	mov rdx, -1
	syscall

	mov	rax, 60		; exit
	mov	rdi, 0
	syscall
