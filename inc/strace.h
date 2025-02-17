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
		if ((long)(call) == -1 && errno != EINTR) {                               \
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

typedef struct {
	pid_t pid;
	int	  status;
	int	  interrupt;
	int	  restart_signal;
	long ptrace_op;

	e_arch		   arch;
	int			   syscall;
	struct rusage  ru;
	struct timeval tv;

	int running : 1;
	int stopped : 1;
	int initial_execve : 1;
	int initial_sigstop : 1;

	summary_t summary;
} data_t;

const char *opts(int argc, char **argv, opt_t *opt);
const char *which(const char *filename);

void handler(int signum);

int trace(data_t *data, const opt_t *opt);

void get_regs(pid_t pid, u_regs *regs);

void on_syscall_start_stop(data_t *td, const opt_t *opt);
void on_syscall_start(data_t *td, const u_regs *regs);
void on_syscall_end(data_t *td, const u_regs *regs);
void print_syscall(data_t *td, const t_syscall_prototype *prototype, long args[MAX_ARGS]);
void print_nosys(int nr, long args[MAX_ARGS]);
void print_initial_execve(long args[MAX_ARGS]);

void on_signal_delivery_stop(data_t *td, const opt_t *opt, int sig);

const t_syscall_prototype *syscall_get_prototype(e_arch arch, unsigned long nr);
const char				*get_format(enum e_type type);

const char *strerrorname(int error);
const char *strerrordesc(int error);
const char *syscall_name(int number);

#endif
