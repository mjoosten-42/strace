#define _GNU_SOURCE // strerrorname_np

#include "arch.h"
#include "strace.h"
#include "syscall.h"

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

int event_loop(pid_t pid, void (*handler)(pid_t, int, int)) {
	void *data	 = NULL;
	int	  status = 0;

	CHECK_SYSCALL(waitpid(pid, &status, 0));

	while (1) {
		CHECK_SYSCALL(ptrace(PTRACE_SYSCALL, pid, NULL, data));
		CHECK_SYSCALL(waitpid(pid, &status, 0));

		data = NULL;

		// Forward signals to tracee
		if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80)) {
			data = (void *)(long)WSTOPSIG(status);
		}

		int signalled = !(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80);

		handler(pid, status, signalled);

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			break;
		}
	}

	return WEXITSTATUS(status);
}

void trace(pid_t pid, int status, int signalled) {
	static e_arch arch	  = X64;
	static int	  running = 0;

	if (signalled && running) {
		eprintf("?\n");
		running = 0;
	}

	// Tracee exited
	if (WIFEXITED(status)) {
		eprintf("+++ exited with %i +++\n", WEXITSTATUS(status));
		return;
	}

	// Tracee terminated by deadly signal
	if (WIFSIGNALED(status)) {
		eprintf(
			"+++ killed by SIG%s %s+++\n", sigabbrev_np(WTERMSIG(status)), WCOREDUMP(status) ? "(core dumped) " : "");
		return;
	}

	// Tracee stopped by signal
	if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80)) {
		siginfo_t siginfo = { 0 };

		CHECK_SYSCALL(ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo));

		const char *abbr = sigabbrev_np(siginfo.si_signo);

		eprintf("--- SIG%s { si_signo=SIG%s, si_code=", abbr, abbr);

		if (siginfo.si_code > 0) {
			eprintf("SI_KERNEL");
		} else {
			eprintf("SI_USER, si_pid = %i, si_uid = %i", siginfo.si_pid, siginfo.si_uid);
		}

		eprintf(" } ---\n");
	}
	// Syscall start-stop
	else {
		u_regs regs = { 0 };

		get_regs(pid, &regs);

		if (!running) {
			on_syscall_start(&regs);
		} else {
			on_syscall_end(&regs);
		}

		if (regs.arch != arch) {
			arch = regs.arch;

			eprintf("[ Process PID=%i runs in %s bit mode. ]\n", pid, arch == X64 ? "64" : "32");
		}

		running = !running;
	}
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
			args[4] = regs->x86_64.r8;
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
		eprintf(prototype->ret.format, ret);
	}

	eprintf("\n");
}

void print_syscall(const t_syscall_prototype *prototype, long args[6]) {
	eprintf("%s(", prototype->name);

	for (int i = 0; i < prototype->argc; i++) {
		// print program name on first execve
		ONCE(eprintf("\"%s\", ", (char *)args[i++]));

		// TODO; print 32 bit pointers with correct size
		if (!strcmp(prototype->args[i].format, "%lu") && args[i] > 0x10000000) {
			eprintf("%p", (void *)args[i]);
		} else {
			eprintf(prototype->args[i].format, args[i]);
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
