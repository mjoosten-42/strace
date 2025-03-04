#define _GNU_SOURCE // strerrorname_np

#include "arch.h"
#include "opt.h"
#include "strace.h"
#include "summary.h"
#include "syscall.h"

#include <asm/unistd.h>
#include <elf.h>
#include <limits.h>
#include <linux/audit.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

int trace(data_t *td, const opt_t *opt) {
	EXIT_IF_FAILED(ptrace(PTRACE_SEIZE, td->pid, NULL, PTRACE_O_TRACESYSGOOD));

	while (!interrupt) {
		IF_FAILED(wait4(td->pid, &td->status, 0, &td->ru)) {
			break;
		}

		td->op	   = PTRACE_SYSCALL;
		td->signal = 0;

		// Syscall interrupted
		if (td->in_syscall && !(WIFSTOPPED(td->status) && WSTOPSIG(td->status) & SYSCALL_BIT)) {
			if (!opt->suppress) {
				eprintf("?\n");
			}

			td->in_syscall = false;
		}

		// Tracee exited
		if (WIFEXITED(td->status)) {
			if (!opt->suppress) {
				eprintf("+++ exited with %i +++\n", WEXITSTATUS(td->status));
			}

			break;
		}

		// Tracee terminated by deadly signal
		if (WIFSIGNALED(td->status)) {
			if (!opt->suppress) {
				eprintf("+++ killed by SIG%s ", sigabbrev_np(WTERMSIG(td->status)));

				if (WCOREDUMP(td->status)) {
					eprintf("(core dumped) ");
				}

				eprintf("+++\n");
			}

			break;
		}

		// Inhibit printing when tracee didn't start
		if (!td->execve_failed) {
			// Tracee received signal
			if (WIFSTOPPED(td->status) && !(WSTOPSIG(td->status) & SYSCALL_BIT)) {
				if (on_signal_delivery_stop(td, opt, WSTOPSIG(td->status))) {
					break;
				}
			}

			// Syscall start-stop
			if (WIFSTOPPED(td->status) && WSTOPSIG(td->status) & SYSCALL_BIT) {
				if (on_syscall_start_stop(td, opt)) {
					break;
				}
			}
		}

		// Restart (or just listen to) tracee
		IF_FAILED(ptrace(td->op, td->pid, NULL, td->signal)) {
			break;
		}
	}

	if (!opt->suppress && (td->in_syscall || interrupt)) {
		td->in_syscall = false;
		eprintf("\n");
	}

	if (opt->summary) {
		summarize(&td->summary);
	}

	// Mimic tracee termsig
	if (WIFSIGNALED(td->status)) {
		signal(WTERMSIG(td->status), SIG_DFL);
		raise(WTERMSIG(td->status));
	}

	return WEXITSTATUS(td->status);
}

int on_syscall_start_stop(data_t *td, const opt_t *opt) {
	struct ptrace_syscall_info	s_info = { 0 };
	struct ptrace_syscall_info *info   = &s_info;

	if (get_regs(td->pid, &s_info)) {
		return 1;
	}

	switch (info->op) {
		case PTRACE_SYSCALL_INFO_ENTRY:
			td->syscall = info->entry.nr;

			if (!opt->suppress) {
				on_syscall_start(td, info);
			}

			if (opt->summary) {
				td->tv = td->ru.ru_stime;
			}

			break;
		case PTRACE_SYSCALL_INFO_EXIT:
			if (!opt->suppress) {
				on_syscall_end(td, info);
			}

			if (opt->summary) {
				count_t *count = NULL;

				switch (td->arch) {
					case AUDIT_ARCH_I386:
						count = &td->summary.count_32[td->syscall];
						break;
					case AUDIT_ARCH_X86_64:
						count = &td->summary.count_64[td->syscall];
						break;
				};

				count->nr = td->syscall;
				count->calls++;
				count->errors += info->exit.is_error;

				tv_sub(&td->ru.ru_stime, &td->tv);
				tv_add(&count->time, &td->ru.ru_stime);
			}

			td->syscall = -1;

			break;
	}

	td->in_syscall = !td->in_syscall;

	if (td->arch != info->arch) {
		td->arch = info->arch;

		eprintf("[ Process PID=%i runs in %s bit mode. ]\n", td->pid, td->arch == AUDIT_ARCH_X86_64 ? "64" : "32");
	}

	return 0;
}

int get_regs(pid_t pid, struct ptrace_syscall_info *info) {
	static bool toggle = false;

	struct registers regs = { 0 };
	struct iovec	 iov  = { &regs.x86_64, sizeof(regs) };

	IF_FAILED(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
		return 1;
	}

	info->op = !toggle ? PTRACE_SYSCALL_INFO_ENTRY : PTRACE_SYSCALL_INFO_EXIT;

	toggle = !toggle;

	switch (iov.iov_len) {
		case sizeof(regs.x86_64):
			info->arch = AUDIT_ARCH_X86_64;

			switch (info->op) {
				case PTRACE_SYSCALL_INFO_ENTRY:
					// rax has already been overwritten
					info->entry.nr		= regs.x86_64.orig_rax;
					info->entry.args[0] = regs.x86_64.rdi;
					info->entry.args[1] = regs.x86_64.rsi;
					info->entry.args[2] = regs.x86_64.rdx;
					info->entry.args[3] = regs.x86_64.r10;
					info->entry.args[5] = regs.x86_64.r8;
					info->entry.args[5] = regs.x86_64.r9;
					break;
				case PTRACE_SYSCALL_INFO_EXIT:
					info->exit.rval		= regs.x86_64.rax;
					info->exit.is_error = info->exit.rval < 0;
					break;
			}

			break;
		case sizeof(regs.i386):
			info->arch = AUDIT_ARCH_I386;

			switch (info->op) {
				case PTRACE_SYSCALL_INFO_ENTRY:
					info->entry.nr		= regs.i386.orig_eax;
					info->entry.args[0] = regs.i386.ebx;
					info->entry.args[1] = regs.i386.ecx;
					info->entry.args[2] = regs.i386.edx;
					info->entry.args[3] = regs.i386.esi;
					info->entry.args[4] = regs.i386.edi;
					info->entry.args[5] = regs.i386.ebp;
					break;
				case PTRACE_SYSCALL_INFO_EXIT:
					info->exit.rval		= regs.i386.eax;
					info->exit.is_error = regs.i386.eax < 0;
					break;
			}

			break;
	}

	return 0;
}

void on_syscall_start(data_t *td, const struct ptrace_syscall_info *info) {
	const t_syscall_prototype *prototype = syscall_get_prototype(info->arch, info->entry.nr);

	if (prototype) {
		print_syscall(td, prototype, info);
	} else {
		print_nosys(info);
	}

	eprintf(") = ");
	fflush(stderr);
}

void print_syscall(data_t *td, const t_syscall_prototype *prototype, const struct ptrace_syscall_info *info) {
	eprintf("%s(", prototype->name);

	if (!td->initial_execve) {
		return print_initial_execve(info);
	}

	for (int i = 0; i < prototype->argc; i++) {
		unsigned long arg	   = info->entry.args[i];
		t_syscall_arg arg_prot = prototype->args[i];

		// Zero out upper 4 bytes if on 32-bit
		if (info->arch == AUDIT_ARCH_I386) {
			arg &= ((1L << 32) - 1);
		}

		if (arg_prot.type == Pointer && arg > (td->arch == AUDIT_ARCH_I386 ? 0x100000 : 0x10000000)) {
			eprintf("%p", (void *)arg);
		} else {
			if (arg_prot.type == Pointer && arg == 0) {
				eprintf("NULL");
			} else {
				eprintf(get_format(arg_prot.type), arg);
			}
		}

		if (i < prototype->argc - 1) {
			eprintf(", ");
		}
	}
}

void print_nosys(const struct ptrace_syscall_info *info) {
	eprintf("syscall_%#lx(", info->entry.nr);

	for (int i = 0; i < MAX_ARGS; i++) {
		eprintf("%#lx%s", info->entry.args[i], i < MAX_ARGS - 1 ? ", " : "");
	}
}

void print_initial_execve(const struct ptrace_syscall_info *info) {
	const char **args = (const char **)(const void *)info->entry.args;

	eprintf("\"%s\", [", (char *)args[0]);

	char **argv = (char **)args[1];

	for (char **p = argv; *p; p++) {
		eprintf("%s\"%s\"", p != argv ? ", " : "", *p);
	}

	int envc = 0;

	for (char **e = (char **)args[2]; *e; e++) {
		envc++;
	}

	eprintf("], %p /* %i vars */", (void *)args[2], envc);
}

void on_syscall_end(data_t *td, const struct ptrace_syscall_info *info) {
	const t_syscall_prototype *prototype = syscall_get_prototype(info->arch, td->syscall);
	long					   ret		 = info->exit.rval;

	if (info->exit.is_error) {
		eprintf("%s %s (%s)", strerrorname_np(-ret) ? "-1" : "?", strerrorname(-ret), strerrordesc(-ret));
	} else {
		eprintf(get_format(prototype->ret.type), ret);
	}

	if (td->syscall == __NR_execve && !td->initial_execve) {
		td->initial_execve = true;

		if (info->exit.is_error) {
			td->execve_failed = true;
		}
	}

	eprintf("\n");
}

int on_signal_delivery_stop(data_t *td, const opt_t *opt, int sig) {
	siginfo_t siginfo = { 0 };
	int		  event	  = td->status >> 16;

	// Ignore initial sigstop
	if (!td->initial_sigstop && sig == SIGSTOP) {
		td->initial_sigstop = 1;

		return 0;
	}

	// Set signal to be delived to tracee
	td->signal = sig;

	IF_FAILED(ptrace(PTRACE_GETSIGINFO, td->pid, NULL, &siginfo)) {
		return 1;
	}

	switch (event) {
		case PTRACE_EVENT_STOP:
			// Result of SIGCONT, for some reason
			if (siginfo.si_signo == SIGTRAP) {
				td->op = PTRACE_SYSCALL;

				break;
			}

			// Don't restart tracee
			td->op	   = PTRACE_LISTEN;
			td->signal = 0;

			if (!opt->suppress) {
				eprintf("--- stopped by SIG%s ---\n", sigabbrev_np(siginfo.si_signo));
			}

			break;
		case 0:
			if (!opt->suppress) {
				const char *abbr = sigabbrev_np(siginfo.si_signo);

				eprintf("--- SIG%s { si_signo=SIG%s, si_code=", abbr, abbr);

				if (siginfo.si_code > 0) {
					eprintf("SI_KERNEL");
				} else {
					eprintf("SI_USER, si_pid=%i, si_uid=%i", siginfo.si_pid, siginfo.si_uid);
				}

				eprintf(" } ---\n");
			}

			break;
	}

	return 0;
}
