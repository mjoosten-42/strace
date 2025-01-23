BITS 32

global _start

_start:
	mov eax, 17
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
