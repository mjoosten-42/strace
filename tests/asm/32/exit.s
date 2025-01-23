BITS 32

global _start

_start:
	mov	eax, 1		; exit
	mov edi, 42
	mov ebx, 0
	int	0x80
