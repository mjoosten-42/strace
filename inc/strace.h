#ifndef STRACE_H
#define STRACE_H

#include "arch.h"
#include "opt.h"
#include "syscall.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define CHECK_SYSCALL(call)                           \
	do {                                              \
		if ((call) == -1) {                           \
			eprintf(#call ": %s\n", strerror(errno)); \
			kill(pid, SIGKILL);                       \
		}                                             \
	} while (0)

#define ONCE(call)           \
	do {                     \
		static int flag = 1; \
                             \
		if (flag) {          \
			(call);          \
			flag = 0;        \
		}                    \
	} while (0)

int trace(pid_t pid, const opt_t *opt);

void get_regs(pid_t pid, u_regs *regs);

void on_syscall_start(const u_regs *regs);
void on_syscall_end(const u_regs *regs);
void print_syscall(const t_syscall_prototype *prototype, long args[6]);
void print_nosys(int nr, long args[6]);

const t_syscall_prototype *syscall_get_prototype(e_arch arch, unsigned long nr);

const char *strerrorname(int error);
const char *strerrordesc(int error);
const char *syscall_name(int number);

const char *which(const char *filename);

void tv_add(struct timespec *out, struct timespec *first, struct timespec *second);
void tv_sub(struct timespec *out, struct timespec *first, struct timespec *second);

#endif
