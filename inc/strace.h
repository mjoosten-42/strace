#ifndef STRACE_H
#define STRACE_H

#include <unistd.h>

long ptrace_wrap(int op, pid_t pid, void *addr, void *data);
void waitpid_wrap(pid_t pid, int *status);

void		trace(pid_t pid_t);
const char *syscall_name(int number);

#endif
