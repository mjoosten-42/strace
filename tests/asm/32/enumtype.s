BITS 32

global _start

%define landlock_add_rule 445

_start:
	mov eax, landlock_add_rule
	mov ebx, -1
	mov ecx, 1
	mov edx, 0
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
