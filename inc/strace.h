#ifndef STRACE_H
#define STRACE_H

#include "syscall.h"

#include <unistd.h>
#include <signal.h>

#define CHECK_SYSCALL(call)		\
	do {						\
		if ((call) == -1) {		\
			perror(#call);		\
			kill(0, SIGKILL);	\
		}						\
	} while (0)

int  trace(pid_t pid_t);

void on_syscall_start(t_syscall_info *info);
void on_syscall_end(t_syscall_info *info);
void on_tracee_exit(t_syscall_info *info, int status);

const char *syscall_name(int number);

#endif
