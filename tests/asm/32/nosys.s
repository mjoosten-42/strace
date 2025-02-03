BITS 32

global _start

_start:
	mov	eax, 222
	mov ebx, 0
	mov ecx, 1
	mov edx, 2
	mov esi, 3
	mov edi, 4
	mov ebp, 5
	int	0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
