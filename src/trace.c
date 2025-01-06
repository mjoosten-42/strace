#define _GNU_SOURCE // strerrorname_np

#include "strace.h"
#include "syscall.h"

#include <sys/user.h>
#include <sys/uio.h>
#include <stdio.h>		// fprintf
#include <stdlib.h>		// exit
#include <string.h>		// strerror
#include <sys/ptrace.h> // ptrace
#include <sys/wait.h>	// waitpid
#include <elf.h>		// NT_PRSTATUS

int trace(pid_t pid) {
	t_syscall_info info	  = { 0 };
	int			   status = 0;

	struct user_regs_struct regs = { 0 };
	struct iovec iov = { &regs, sizeof(regs) };
	
	CHECK_SYSCALL(waitpid(pid, &status, 0));

	while (1) {
		// Continue until next syscall
		CHECK_SYSCALL(ptrace(PTRACE_SYSCALL, pid, NULL, NULL));
		CHECK_SYSCALL(waitpid(pid, &status, 0));

		if (WIFEXITED(status)) {
			on_tracee_exit(&info, status);
			break;
		}

		if (WIFSIGNALED(status)) {
			on_tracee_signalled(&info, status);
			break;
		}

		if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80)) {
			on_tracee_stopped(&info, status);
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
	info->prototype = syscall_get_prototype(regs->orig_rax);

	eprintf("%s(", info->prototype->name);

	switch (info->prototype->argc) {
		case 6:
			eprintf("%llx", regs->r9);
			eprintf(", ");
			__attribute__((fallthrough));
		case 5:
			eprintf("%llx", regs->r8);
			eprintf(", ");
			__attribute__((fallthrough));
		case 4:
			eprintf("%llx", regs->rcx);
			eprintf(", ");
			__attribute__((fallthrough));
		case 3:
			eprintf("%llx", regs->rdx);
			eprintf(", ");
			__attribute__((fallthrough));
		case 2:
			eprintf("%llx", regs->rsi);
			eprintf(", ");
			__attribute__((fallthrough));
		case 1:
			eprintf("%llx", regs->rdi);
		default:
			break;
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

void on_tracee_stopped(t_syscall_info *info, int status) {
	if (info->running) {
		eprintf("?\n");
	}
	
	eprintf("--- %s ---\n", getsigname(WSTOPSIG(status) & ~0x80));
}

void on_tracee_signalled(t_syscall_info *info, int status) {
	if (info->running) {
		eprintf("?\n");
	}
	
	eprintf("+++ terminated with %s +++\n", getsigname(WTERMSIG(status)));
}

