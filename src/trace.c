#define _GNU_SOURCE // strerrorname_np

#include "arch.h"
#include "opt.h"
#include "strace.h"
#include "syscall.h"
#include "count.h"

#include <elf.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>

int trace(pid_t pid, const opt_t *opt) {
	e_arch arch	   = X64;
	int	   running = 0;
	int	   status  = 0;
	void	 *data	   = NULL;
	struct timespec start = { 0 };
	counts_t counts = { 0 };

	while (1) {
		CHECK_SYSCALL(ptrace(PTRACE_SYSCALL, pid, NULL, data));
		CHECK_SYSCALL(waitpid(pid, &status, 0));

		data = NULL;

		// Syscall interrupted
		if (!(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) && running) {
			if (!opt->summary) {
				eprintf("?\n");
			}

			running = 0;
		}

		// Tracee exited
		if (WIFEXITED(status)) {
			if (!opt->summary) {
				eprintf("+++ exited with %i +++\n", WEXITSTATUS(status));
			}

			break;
		}

		// Tracee terminated by deadly signal
		if (WIFSIGNALED(status)) {
			if (!opt->summary) {
				eprintf("+++ killed by SIG%s ", sigabbrev_np(WTERMSIG(status)));

				if (WCOREDUMP(status)) {
					eprintf("(core dumped) ");
				}

				eprintf("+++\n");
			}

			break;
		}

		// Tracee stopped by signal
		if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80)) {
			siginfo_t siginfo = { 0 };

			CHECK_SYSCALL(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo));

			const char *abbr = sigabbrev_np(siginfo.si_signo);

			if (!opt->summary) {
				eprintf("--- SIG%s { si_signo=SIG%s, si_code=", abbr, abbr);

				if (siginfo.si_code > 0) {
					eprintf("SI_KERNEL");
				} else {
					eprintf("SI_USER, si_pid=%i, si_uid=%i", siginfo.si_pid, siginfo.si_uid);
				}
			}

			// Forward signals to tracee
			data = (void *)(long)WSTOPSIG(status);
		}

		if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
			u_regs regs = { 0 };

			get_regs(pid, &regs);

			if (!opt->summary) {
				if (!running) {
					on_syscall_start(&regs);
				} else {
					on_syscall_end(&regs);
				}
			}

			if (opt->summary || opt->time) {
				struct timespec current = { 0 };

				CHECK_SYSCALL(clock_gettime(CLOCK_MONOTONIC, &current));

				if (!running) {
					start = current;
				} else {
					tv_sub(&current, &start);

					count_t *count = NULL;

					switch (regs.arch) {
						case X32:
							count = &counts.count_32[regs.nr];
							break;
						case X64:
							count = &counts.count_64[regs.nr];
							break;
					};

					count->nr = regs.nr;
					count->calls++;
					tv_add(&count->total, &current);

					if (regs.ret < 0) {
						count->errors++;
					}

					if (opt->time) {
						eprintf(" <%li.%06li>", current.tv_sec, current.tv_nsec / 1000);
					}
				}
			}
		
			if (!opt->summary && running) {
				eprintf("\n");
			}

			running = !running;
			
			if (regs.arch != arch) {
				arch = regs.arch;

				eprintf("[ Process PID=%i runs in %s bit mode. ]\n", pid, arch == X64 ? "64" : "32");
			}
		}
	}

	if (opt->summary) {
		count(&counts);
	}

	return status;
}

void get_regs(pid_t pid, u_regs *regs) {
	struct iovec iov = { &regs->x86_64, sizeof(*regs) };

	// read registers
	CHECK_SYSCALL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

	regs->arch = (iov.iov_len == sizeof(regs->x86_64) ? X64 : X32);

	switch (regs->arch) {
		case X32:
			regs->nr  = regs->x86.orig_eax;
			regs->ret = regs->x86.eax;
			break;
		case X64:
			regs->nr  = regs->x86_64.orig_rax;
			regs->ret = regs->x86_64.rax;
			break;
	};
}

void on_syscall_start(const u_regs *regs) {
	long args[6] = { 0 };

	switch (regs->arch) {
		case X64:
			args[0] = regs->x86_64.rdi;
			args[1] = regs->x86_64.rsi;
			args[2] = regs->x86_64.rdx;
			args[3] = regs->x86_64.r10;
			args[5] = regs->x86_64.r8;
			args[5] = regs->x86_64.r9;
			break;
		case X32:
			args[0] = regs->x86.ebx;
			args[1] = regs->x86.ecx;
			args[2] = regs->x86.edx;
			args[3] = regs->x86.esi;
			args[4] = regs->x86.edi;
			args[5] = regs->x86.ebp;
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

void print_syscall(const t_syscall_prototype *prototype, long args[6]) {
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

void print_nosys(int nr, long args[6]) {
	eprintf("syscall_%#x(", nr);

	for (int i = 0; i < 6; i++) {
		eprintf("%#lx%s", args[i], i < 5 ? ", " : "");
	}

	eprintf(") = ");
}
