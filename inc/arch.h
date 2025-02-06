#ifndef ARCH_H
#define ARCH_H

#include <stdint.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define SYSCALL_X86_MAX 466
#define SYSCALL_X86_64_MAX 548

#define SYSCALL_MAX MAX(SYSCALL_X86_MAX, SYSCALL_X86_64_MAX)

typedef enum {
	X32,
	X64,
} e_arch;

typedef struct {
	e_arch arch;
	int	   nr;
	long   ret;

	union {
		struct {
			int32_t ebx;
			int32_t ecx;
			int32_t edx;
			int32_t esi;
			int32_t edi;
			int32_t ebp;
			int32_t eax;
			int32_t xds;
			int32_t xes;
			int32_t xfs;
			int32_t xgs;
			int32_t orig_eax;
			int32_t eip;
			int32_t xcs;
			int32_t eflags;
			int32_t esp;
			int32_t xss;
		} x86;

		struct {
			uint64_t r15;
			uint64_t r14;
			uint64_t r13;
			uint64_t r12;
			uint64_t rbp;
			uint64_t rbx;
			uint64_t r11;
			uint64_t r10;
			uint64_t r9;
			uint64_t r8;
			uint64_t rax;
			uint64_t rcx;
			uint64_t rdx;
			uint64_t rsi;
			uint64_t rdi;
			uint64_t orig_rax;
			uint64_t rip;
			uint64_t cs;
			uint64_t eflags;
			uint64_t rsp;
			uint64_t ss;
			uint64_t fs_base;
			uint64_t gs_base;
			uint64_t ds;
			uint64_t es;
			uint64_t fs;
			uint64_t gs;
		} x86_64;
	};
} u_regs;

#endif
