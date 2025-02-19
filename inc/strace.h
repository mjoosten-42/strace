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
#define ptrace_syscall_info __ptrace_syscall_info
#define SYSCALL_BIT 0x80

#define CHECK_SYSCALL(call)                                                       \
	do {                                                                          \
		if ((long)(call) < 0L) {                                                  \
			eprintf(#call ": %s: %s\n", strerrorname_np(errno), strerror(errno)); \
		}                                                                         \
	} while (0)

typedef struct {
	pid_t pid;
	int	  status;
	int	  interrupt;
	int	  signal;
	long  op;

	int			   syscall;
	unsigned int   arch;
	struct rusage  ru;
	struct timeval tv;

	int running : 1;
	int initial_execve : 1;
	int initial_sigstop : 1;

	summary_t summary;
} data_t;

const char *opts(int argc, char **argv, opt_t *opt);
const char *which(const char *filename);

void handler(int signum);

int trace(data_t *data, const opt_t *opt);

void get_regs(pid_t pid, struct ptrace_syscall_info *info);

void on_syscall_start_stop(data_t *td, const opt_t *opt);
void on_syscall_start(data_t *td, const struct ptrace_syscall_info *info);
void on_syscall_end(data_t *td, const struct ptrace_syscall_info *info);
void print_syscall(data_t *td, const t_syscall_prototype *prototype, const struct ptrace_syscall_info *info);
void print_nosys(const struct ptrace_syscall_info *info);
void print_initial_execve(const struct ptrace_syscall_info *info);

void on_signal_delivery_stop(data_t *td, const opt_t *opt, int sig);

const t_syscall_prototype *syscall_get_prototype(int arch, int nr);
const char				*get_format(enum e_type type);

const char *strerrorname(int error);
const char *strerrordesc(int error);
const char *syscall_name(int number);

#endif
