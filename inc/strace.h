#ifndef STRACE_H
#define STRACE_H

#include "arch.h"
#include "opt.h"
#include "summary.h"
#include "syscall.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define CHECK_SYSCALL(call)                                                       \
	do {                                                                          \
		if ((call) == -1 && errno != EINTR) {                                     \
			eprintf(#call ": %s: %s\n", strerrorname_np(errno), strerror(errno)); \
			raise(SIGKILL);                                                       \
		}                                                                         \
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

#define MAX_ARGS 6

typedef struct {
	int		  status;
	int		  running;
	int		  interrupt;
	summary_t summary;
} data_t;

const char *opts(int argc, char **argv, opt_t *opt);
const char *which(const char *filename);

void handler(int signum);
void terminate();

int trace(pid_t pid, data_t *data, const opt_t *opt);

void get_regs(pid_t pid, u_regs *regs);

void on_syscall_start(const u_regs *regs);
void on_syscall_end(const u_regs *regs);
void print_syscall(const t_syscall_prototype *prototype, long args[MAX_ARGS]);
void print_nosys(int nr, long args[MAX_ARGS]);

const t_syscall_prototype *syscall_get_prototype(e_arch arch, unsigned long nr);
const char				*get_format(enum e_type type);

const char *strerrorname(int error);
const char *strerrordesc(int error);
const char *syscall_name(int number);

#endif
