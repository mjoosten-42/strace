BITS 32

global _start

%include "defines.s"

handler:
	ret

restorer:
	mov eax, sigreturn
	int 0x80

_start:
	push 0
	push 0
	push handler

	mov	eax, sigaction
	mov	ebx, SIGALRM
	mov ecx, esp
	mov	edx, 0
	int 0x80

	mov	eax, alarm
	mov	ebx, 1
	int 0x80

	mov	eax, pause
	int 0x80

	mov	eax, exit
	mov	ebx, 0
	int 0x80
