global _start

%include "defines.s"

struc pollfd
	fd:	resd 1
	in: resw 1
	out: resw 1
endstruc

_start:
	mov rcx, rsp
	sub rsp, 8
	mov	DWORD [rcx + 0], 0
	mov WORD  [rcx + 4], 1
	mov WORD  [rcx + 6], 0
	mov	rax, poll
	mov	rdi, rcx
	mov	rsi, 1
	mov rdx, -1
	syscall

	mov	rax, exit
	mov	rdi, 0
	syscall
