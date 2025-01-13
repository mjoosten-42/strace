#define _GNU_SOURCE // strerrorname_np

#include "strace.h"
#include "syscall.h"

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

		if ((WIFEXITED(status) || WIFSIGNALED(status) ||
			(WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80))) && info.running) {
			eprintf("?\n");
			info.running = 0;
		}

		if (WIFEXITED(status)) {
			on_tracee_exit(&info, status);
			break;
		}

		if (WIFSIGNALED(status)) {
			on_tracee_signalled(&info, status);
			break;
		}

		CHECK_SYSCALL(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo));

		if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80)) {
			on_tracee_stopped(&info, status, &siginfo);

			// set data to signal to be delivered to tracee
			data = (void *)(unsigned long)WSTOPSIG(status);
		}

		CHECK_SYSCALL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov));

		if (!info.running) {
			on_syscall_start(&info, &regs);
			info.running = 1;
		} else {
			on_syscall_end(&info, &regs);
			info.running = 0;
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
		eprintf("%i %s (%s)", -1, strerrorname_np(-ret), strerror(-ret));
	} else {
		eprintf(info->prototype->ret.format, ret);
	}

	eprintf("\n");
}

void on_tracee_exit(t_syscall_info *info, int status) {
	if (info->running) {
		eprintf("?\n");
	}

	eprintf("+++ exited with %i +++\n", WEXITSTATUS(status));
}

void on_tracee_stopped(t_syscall_info *info, int status, siginfo_t *siginfo) {
	if (info->running) {
		eprintf("?\n");
	}

	const char *abbr = sigabbrev_np(WSTOPSIG(status) & ~0x80);

	eprintf("--- SIG%s { si_signo = SIG%s, si_pid = %d } ---\n", abbr, abbr, siginfo->si_pid);
}

void on_tracee_signalled(t_syscall_info *info, int status) {
	if (info->running) {
		eprintf("?\n");
	}

	eprintf("+++ terminated with SIG%s +++\n", sigabbrev_np(WTERMSIG(status)));
}
