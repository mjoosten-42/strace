#ifndef SYSCALL_H
#define SYSCALL_H

typedef struct s_arg_info{
	char type[64];
	char format[4];
	int	 size;
} arg_info;

typedef struct s_syscall_info {
	int	 nr;
	int	 argc;
	char name[32];
	arg_info ret;
	arg_info args[6];
} syscall_info;

const syscall_info *get_syscall_info(int nr);

#endif
