#define _GNU_SOURCE // strerrorname_np

#include "arch.h"
#include "strace.h"
#include "syscall.h"

#include <assert.h>
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

int trace(pid_t pid) {
	t_syscall_info info	  = { 0 };
	int			   status = 0;
	e_arch		   arch	  = X64;

	siginfo_t	 siginfo = { 0 };
	u_regs		 regs	 = { 0 };
	struct iovec iov	 = { &regs.x86_64, sizeof(regs) };

	void *addr = NULL;
	void *data = NULL;

	CHECK_SYSCALL(waitpid(pid, &status, 0));

	while (1) {
		iov.iov_len = sizeof(regs);

		// Continue until next syscall
		CHECK_SYSCALL(ptrace(PTRACE_SYSCALL, pid, addr, data));
		CHECK_SYSCALL(waitpid(pid, &status, 0));

		addr = NULL;
		data = NULL;

		int signalled = !((WIFSTOPPED(status) && WSTOPSIG(status) & 0x80));

		if (signalled && info.running) {
			eprintf("?\n");
			info.running = 0;
		}

		if (WIFEXITED(status)) {
			eprintf("+++ exited with %i +++\n", WEXITSTATUS(status));
			break;
		}

		if (WIFSIGNALED(status)) {
			eprintf("+++ killed by SIG%s %s+++\n",
					sigabbrev_np(WTERMSIG(status)),
					WCOREDUMP(status) ? "(core dumped) " : "");
			break;
		}

		if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80)) {
			CHECK_SYSCALL(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo));

			const char *abbr = sigabbrev_np(siginfo.si_signo);

			eprintf("--- SIG%s { si_signo = SIG%s", abbr, abbr);

			if (siginfo.si_code > 0) {
				eprintf(", si_code = SI_KERNEL");
			} else {
				eprintf(", si_code = SI_USER, si_pid = %i, si_uid = %i", siginfo.si_pid, siginfo.si_uid);
			}

			eprintf(" } ---\n");

			// set data to signal to be delivered to tracee
			data = (void *)(long)(WSTOPSIG(status) & ~0x80);
		} else {
			// read registers
			CHECK_SYSCALL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

			regs.arch = (iov.iov_len == sizeof(regs.x86_64) ? X64 : X32);

			if (!info.running) {
				on_syscall_start(&info, &regs);
			} else {
				on_syscall_end(&info, &regs);
			}

			if (regs.arch != arch) {
				arch = regs.arch;

				eprintf("[ Process PID = %i runs in %s bit mode. ]\n", pid, arch == X64 ? "64" : "32");
			}

			info.running = !info.running;
		}
	}

	return WEXITSTATUS(status);
}

void on_syscall_start(t_syscall_info *info, const u_regs *regs) {
	long nr		 = 0;
	long args[6] = { 0 };

	switch (regs->arch) {
		case X64:
			nr		= regs->x86_64.orig_rax;
			args[0] = regs->x86_64.rdi;
			args[1] = regs->x86_64.rsi;
			args[2] = regs->x86_64.rdx;
			args[3] = regs->x86_64.rcx;
			args[4] = regs->x86_64.r8;
			args[5] = regs->x86_64.r9;
			break;
		case X32:
			nr		= regs->x86.orig_eax;
			args[0] = regs->x86.ebx;
			args[1] = regs->x86.ecx;
			args[2] = regs->x86.edx;
			args[3] = regs->x86.esi;
			args[4] = regs->x86.edi;
			args[5] = regs->x86.ebp;
			break;
	};

	info->prototype = syscall_get_prototype(nr);

	eprintf("%s(", info->prototype->name);

	for (int i = 0; i < info->prototype->argc; i++) {
		eprintf(info->prototype->args[i].format, args[i]);

		if (i < info->prototype->argc - 1) {
			eprintf(", ");
		}
	}

	eprintf(") = ");
}

void on_syscall_end(t_syscall_info *info, const u_regs *regs) {
	long ret = 0;

	switch (regs->arch) {
		case X64:
			ret = regs->x86_64.rax;
			break;
		case X32:
			ret = regs->x86.eax;
			break;
	};

	if (ret < 0) {
		// kernel-only errors such as ERESTART do not have a corresponding user
		// error string.
		if (strerrorname_np(-ret) == NULL) {
			eprintf("? ");
		} else {
			eprintf("%i ", -1);
		}

		eprintf("%s (%s)", strerrorname(-ret), strerrordesc(-ret));
	} else {
		if (ret > INT_MAX) {
			eprintf("%p", (void *)ret);
		} else {
			eprintf("%li", ret);
		}
		// TODO: pagesize
	}
	(void)info;

	eprintf("\n");
}
