#define _GNU_SOURCE // strerrorname_np

#include "strace.h"
#include "syscall.h"

#include <assert.h>
#include <elf.h>
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

	siginfo_t				siginfo = { 0 };
	struct user_regs_struct regs	= { 0 };
	struct iovec			iov		= { &regs, sizeof(regs) };

	void *addr = NULL;
	void *data = NULL;

	CHECK_SYSCALL(waitpid(pid, &status, 0));

	while (1) {
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

			eprintf("--- SIG%s { si_signo = SIG%s, si_code = %s } ---\n",
				abbr,
				abbr,
				siginfo.si_code <= 0 ? "SI_USER" : "SI_KERNEL");

			// set data to signal to be delivered to tracee
			data = (void *)(unsigned long)(WSTOPSIG(status) & ~0x80);
		} else {
			// read registers
			CHECK_SYSCALL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

			if (!info.running) {
				on_syscall_start(&info, &regs);
			} else {
				on_syscall_end(&info, &regs);
			}

			info.running = !info.running;
		}
	}

	return WEXITSTATUS(status);
}

void on_syscall_start(t_syscall_info *info, struct user_regs_struct *regs) {
	long args[] = {
		regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9,
	};

	info->prototype = syscall_get_prototype(regs->orig_rax);

	eprintf("%s(", info->prototype->name);

	for (int i = 0; i < info->prototype->argc; i++) {
		eprintf(info->prototype->args[i].format, args[i]);

		if (i < info->prototype->argc - 1) {
			eprintf(", ");
		}
	}

	eprintf(") = ");
}

void on_syscall_end(t_syscall_info *info, struct user_regs_struct *regs) {
	long ret = regs->rax;

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
		eprintf(info->prototype->ret.format, ret);
	}

	eprintf("\n");
}

