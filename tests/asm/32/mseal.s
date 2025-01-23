BITS 32

global _start

_start:
	mov eax, 462
	mov ebx, 0
	mov ecx, 0
	mov edx, 0
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
