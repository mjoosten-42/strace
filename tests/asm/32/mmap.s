BITS 32

global _start

_start:
	mov eax, 90
	mov ebx, -1
	mov ecx, 4096
	mov edx, 0
	mov esi, -1
	mov edi, 0
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
