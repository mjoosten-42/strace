#ifndef SYSCALL_H
#define SYSCALL_H

typedef struct s_arg {
	char format[4];
	int	 size;
} arg;

typedef struct s_syscall_info {
	int	 nr;
	char name[32];
	int	 argc;
	arg	 args[6];
} syscall_info;

const syscall_info *get_syscall_info(int nr);

#endif
