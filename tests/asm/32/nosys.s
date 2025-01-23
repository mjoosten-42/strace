BITS 32

global _start

_start:
	mov	eax, 222
	mov ebx, 0
	mov ecx, -1
	mov edx, 0xFFFFFFFF
	mov esi, 0x8FFFFFFF
	mov edi, 42
	int	0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
