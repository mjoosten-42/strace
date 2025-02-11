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

int trace(pid_t pid, data_t *td, const opt_t *opt) {
	e_arch		   arch	 = ARCH_X86_64;
	void		  *data	 = NULL;
	struct timeval start = { 0 };
	struct rusage  ru	 = { 0 };

	while (1) {
		CHECK_SYSCALL(ptrace(PTRACE_SYSCALL, pid, NULL, data));
		CHECK_SYSCALL(wait4(pid, &td->status, 0, opt->summary ? &ru : NULL));

		data = NULL;

		// Syscall interrupted
		if (!(WIFSTOPPED(td->status) && WSTOPSIG(td->status) & 0x80) && td->running) {
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

		// Tracee stopped by signal
		if (WIFSTOPPED(td->status) && !(WSTOPSIG(td->status) & 0x80)) {
			siginfo_t siginfo = { 0 };

			CHECK_SYSCALL(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo));

			const char *abbr = sigabbrev_np(siginfo.si_signo);

			if (!opt->suppress) {
				eprintf("--- SIG%s { si_signo=SIG%s, si_code=", abbr, abbr);

				if (siginfo.si_code > 0) {
					eprintf("SI_KERNEL");
				} else {
					eprintf("SI_USER, si_pid=%i, si_uid=%i", siginfo.si_pid, siginfo.si_uid);
				}

				eprintf(" } ---\n");
			}

			// Forward signals to tracee
			data = (void *)(long)WSTOPSIG(td->status);
		}

		// Syscall start-stop
		if (WIFSTOPPED(td->status) && WSTOPSIG(td->status) & 0x80) {
			u_regs regs = { 0 };

			get_regs(pid, &regs);

			if (!opt->suppress) {
				if (!td->running) {
					on_syscall_start(&regs);
				} else {
					on_syscall_end(&regs);
				}
			}

			// Time
			if (opt->summary) {
				if (!td->running) {
					start = ru.ru_stime;
				} else {
					count_t *count = NULL;

					switch (regs.arch) {
						case ARCH_I386:
							count = &td->summary.count_32[regs.nr];
							break;
						case ARCH_X86_64:
							count = &td->summary.count_64[regs.nr];
							break;
					};

					count->nr = regs.nr;
					count->calls++;
					count->errors += (regs.ret < 0);

					tv_sub(&ru.ru_stime, &start);
					tv_add(&count->time, &ru.ru_stime);
				}
			}

			if (!opt->suppress && td->running) {
				eprintf("\n");
			}

			td->running = !td->running;

			if (regs.arch != arch) {
				arch = regs.arch;

				eprintf("[ Process PID=%i runs in %s bit mode. ]\n", pid, arch == ARCH_X86_64 ? "64" : "32");
			}
		}

		if (td->interrupt) {
			break;
		}
	}

	if (opt->summary) {
		summarize(&td->summary);
	}

	return td->status;
}

void get_regs(pid_t pid, u_regs *regs) {
	struct iovec iov = { &regs->x86_64, sizeof(*regs) };

	// read registers
	CHECK_SYSCALL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

	regs->arch = (iov.iov_len == sizeof(regs->x86_64) ? ARCH_X86_64 : ARCH_I386);

	switch (regs->arch) {
		case ARCH_I386:
			regs->nr  = regs->x86.orig_eax;
			regs->ret = regs->x86.eax;
			break;
		case ARCH_X86_64:
			regs->nr  = regs->x86_64.orig_rax;
			regs->ret = regs->x86_64.rax;
			break;
	};
}

void on_syscall_start(const u_regs *regs) {
	long args[6] = { 0 };

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
		print_syscall(prototype, args);
	} else {
		print_nosys(regs->nr, args);
	}
}

void on_syscall_end(const u_regs *regs) {
	const t_syscall_prototype *prototype = syscall_get_prototype(regs->arch, regs->nr);
	long					   ret		 = regs->ret;

	if (ret < 0) {
		eprintf("%s %s (%s)", strerrorname_np(-ret) ? "-1" : "?", strerrorname(-ret), strerrordesc(-ret));
	} else {
		eprintf(get_format(prototype->ret.type), ret);
	}
}

void print_syscall(const t_syscall_prototype *prototype, long args[MAX_ARGS]) {
	eprintf("%s(", prototype->name);

	for (int i = 0; i < prototype->argc; i++) {
		t_syscall_arg arg = prototype->args[i];

		// print program name on first execve
		ONCE(eprintf("\"%s\", ", (char *)args[i++]));

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
