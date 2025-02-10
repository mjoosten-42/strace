#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/ptrace.h>

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
	int	 size;
} t_syscall_arg;

typedef struct s_syscall_prototype {
	char		  name[32];
	int			  argc;
	t_syscall_arg ret;
	t_syscall_arg args[6];
} t_syscall_prototype;

#endif
