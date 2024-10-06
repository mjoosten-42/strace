#ifndef STRACE_H
#define STRACE_H

#include <unistd.h>

long ptrace_wrap(int op, ...);
void waitpid_wrap(pid_t pid, int *status);
void trace(pid_t pid_t);

#endif
