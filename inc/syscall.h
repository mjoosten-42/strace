#ifndef SYSCALL_H
#define SYSCALL_H

#include <sys/ptrace.h>

typedef struct s_syscall_arg {
	char format[8];
	int	 size;
} t_syscall_arg;

typedef struct s_syscall_prototype {
	char		  name[32];
	int			  argc;
	t_syscall_arg ret;
	t_syscall_arg args[6];
} t_syscall_prototype;

typedef struct s_syscall_info {
	struct __ptrace_syscall_info values;
	const t_syscall_prototype	  *prototype;
	unsigned int				 running : 1;
} t_syscall_info;

#endif
