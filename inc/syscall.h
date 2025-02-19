#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/ptrace.h>

#define MAX_ARGS 6

enum e_type {
	Int,
	UInt,
	Long,
	ULong,
	Pointer,
	Enum,
};

typedef struct {
	enum e_type type;
	int			size;
} t_syscall_arg;

typedef struct {
	char		  name[32];
	int			  argc;
	t_syscall_arg ret;
	t_syscall_arg args[MAX_ARGS];
} t_syscall_prototype;

#endif
