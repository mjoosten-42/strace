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

typedef struct s_syscall_arg {
	enum e_type type;
	int			size;
} t_syscall_arg;

typedef struct s_syscall_prototype {
	char		  name[32];
	int			  argc;
	t_syscall_arg ret;
	t_syscall_arg args[MAX_ARGS];
} t_syscall_prototype;

#endif
