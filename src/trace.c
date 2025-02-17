#define _GNU_SOURCE // strerrorname_np

#include "arch.h"
#include "opt.h"
#include "strace.h"
#include "summary.h"
#include "syscall.h"

#include <elf.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#define SYSCALL_BIT 0x80

int trace(data_t *td, const opt_t *opt) {
	CHECK_SYSCALL(ptrace(PTRACE_SEIZE, td->pid, NULL, PTRACE_O_TRACESYSGOOD));

	while (!td->interrupt) {
		CHECK_SYSCALL(wait4(td->pid, &td->status, 0, &td->ru));

		td->restart_signal = 0;
		td->ptrace_op = PTRACE_SYSCALL;

		// Syscall interrupted
		if (!(WIFSTOPPED(td->status) && WSTOPSIG(td->status) & SYSCALL_BIT) && td->running) {
			if (!opt->suppress) {
				eprintf("?\n");
			}

			td->running = 0;
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

		// Tracee received signal
		if (WIFSTOPPED(td->status) && !(WSTOPSIG(td->status) & SYSCALL_BIT)) {
			on_signal_delivery_stop(td, opt, WSTOPSIG(td->status));

		}

		// Syscall start-stop
		if (WIFSTOPPED(td->status) && WSTOPSIG(td->status) & SYSCALL_BIT) {
			on_syscall_start_stop(td, opt);
		}

		eprintf(" [ Ptrace(%s, sig: %2d) ] ", td->ptrace_op == PTRACE_SYSCALL ? "PTRACE_SYSCALL" : "PTRACE_LISTEN", td->restart_signal);
		CHECK_SYSCALL(ptrace(td->ptrace_op, td->pid, NULL, td->restart_signal));
	}

	if (opt->summary) {
		summarize(&td->summary);
	}

	return td->status;
}

void on_syscall_start_stop(data_t *td, const opt_t *opt) {
	u_regs regs = { 0 };

	get_regs(td->pid, &regs);

	// Syscall entry
	if (!td->running) {
		td->syscall = regs.nr;

		if (!opt->suppress) {
			on_syscall_start(td, &regs);
		}

		if (opt->summary) {
			td->tv = td->ru.ru_stime;
		}
	}

	// Syscall exit
	if (td->running) {
		if (!opt->suppress) {
			on_syscall_end(td, &regs);
		}

		if (opt->summary) {
			count_t *count = NULL;

			switch (td->arch) {
				case ARCH_I386:
					count = &td->summary.count_32[td->syscall];
					break;
				case ARCH_X86_64:
					count = &td->summary.count_64[td->syscall];
					break;
			};

			count->nr = td->syscall;
			count->calls++;
			count->errors += (regs.ret < 0);

			tv_sub(&td->ru.ru_stime, &td->tv);
			tv_add(&count->time, &td->ru.ru_stime);
		}

		td->syscall = -1;
	}

	td->running = !td->running;

	if (regs.arch != td->arch) {
		td->arch = regs.arch;

		eprintf("[ Process PID=%i runs in %s bit mode. ]\n", td->pid, td->arch == ARCH_X86_64 ? "64" : "32");
	}
}

void get_regs(pid_t pid, u_regs *regs) {
	struct iovec iov = { &regs->x86_64, sizeof(*regs) };

	// read registers
	CHECK_SYSCALL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

	switch (iov.iov_len) {
		case sizeof(regs->x86_64):
			regs->arch = ARCH_X86_64;
			regs->nr   = regs->x86_64.orig_rax;
			regs->ret  = regs->x86_64.rax;
			break;
		case sizeof(regs->x86):
			regs->arch = ARCH_I386;
			regs->nr   = regs->x86.orig_eax;
			regs->ret  = regs->x86.eax;
			break;
		default:
			break;
	};
}

void on_syscall_start(data_t *td, const u_regs *regs) {
	long args[MAX_ARGS] = { 0 };

	switch (regs->arch) {
		case ARCH_I386:
			args[0] = regs->x86.ebx;
			args[1] = regs->x86.ecx;
			args[2] = regs->x86.edx;
			args[3] = regs->x86.esi;
			args[4] = regs->x86.edi;
			args[5] = regs->x86.ebp;
			break;
		case ARCH_X86_64:
			args[0] = regs->x86_64.rdi;
			args[1] = regs->x86_64.rsi;
			args[2] = regs->x86_64.rdx;
			args[3] = regs->x86_64.r10;
			args[5] = regs->x86_64.r8;
			args[5] = regs->x86_64.r9;
			break;
	};

	const t_syscall_prototype *prototype = syscall_get_prototype(regs->arch, regs->nr);

	if (prototype) {
		print_syscall(td, prototype, args);
	} else {
		print_nosys(regs->nr, args);
	}
}

void on_syscall_end(data_t *td, const u_regs *regs) {
	const t_syscall_prototype *prototype = syscall_get_prototype(regs->arch, td->syscall);
	long					   ret		 = regs->ret;

	if (ret < 0) {
		eprintf("%s %s (%s)", strerrorname_np(-ret) ? "-1" : "?", strerrorname(-ret), strerrordesc(-ret));
	} else {
		eprintf(get_format(prototype->ret.type), ret);
	}

	eprintf("\n");
}

void print_syscall(data_t *td, const t_syscall_prototype *prototype, long args[MAX_ARGS]) {
	eprintf("%s(", prototype->name);

	if (!td->initial_execve) {
		td->initial_execve = 1;

		return print_initial_execve(args);
	}

	for (int i = 0; i < prototype->argc; i++) {
		t_syscall_arg arg = prototype->args[i];

		// TODO; print 32 bit pointers with correct size
		if (arg.type == Pointer && args[i] > 0x10000000) {
			eprintf("%p", (void *)args[i]);
		} else {
			eprintf(get_format(arg.type), args[i]);
		}

		if (i < prototype->argc - 1) {
			eprintf(", ");
		}
	}

	eprintf(") = ");
}

void print_nosys(int nr, long args[MAX_ARGS]) {
	eprintf("syscall_%#x(", nr);

	for (int i = 0; i < MAX_ARGS; i++) {
		eprintf("%#lx%s", args[i], i < MAX_ARGS - 1 ? ", " : "");
	}

	eprintf(") = ");
}

void print_initial_execve(long args[MAX_ARGS]) {
	eprintf("\"%s\", [", (char *)args[0]);

	char **argv = (char **)args[1];

	for (char **p = argv; *p; p++) {
		eprintf("%s\"%s\"", p != argv ? ", " : "", *p);
	}

	int envc = 0;

	for (char **e = (char **)args[2]; *e; e++) {
		envc++;
	}

	eprintf("], %p /* %i vars */ ) = ", (void *)args[2], envc);
}

void on_signal_delivery_stop(data_t *td, const opt_t *opt, int sig) {
	// Ignore initial sigstop
	if (!td->initial_sigstop && sig == SIGSTOP) {
		td->initial_sigstop = 1;

		return;
	}
	
	td->restart_signal = sig;
		
	siginfo_t siginfo = { 0 };
	int event = td->status >> 16;
	int ret = 0;

	CHECK_SYSCALL(ret = ptrace(PTRACE_GETSIGINFO, td->pid, NULL, &siginfo));

	if (event == PTRACE_EVENT_STOP) {
		td->ptrace_op = PTRACE_LISTEN;
		td->restart_signal = 0;
		
		if (!opt->suppress) {
			eprintf("--- stopped by SIG%s ---\n", sigabbrev_np(siginfo.si_signo));
		}

		eprintf(" [ Unsetting ] ");
	}

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

}
