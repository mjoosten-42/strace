#include "strace.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

void trace(pid_t pid) {
	struct __ptrace_syscall_info info = { 0 };
	int options = PTRACE_O_TRACESYSGOOD;
	int status	= 0;

	waitpid(pid, &status, 0);
	ptrace_wrap(PTRACE_SETOPTIONS, pid, NULL, options);

	while (1) {
		ptrace_wrap(PTRACE_GET_SYSCALL_INFO, pid, NULL, &info);

		fprintf(stderr, "op: %i\n", info.op);

		if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
			fprintf(stderr, "syscall: %lu", info.entry.nr);
		}

		if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
			fprintf(stderr, " = %li\n", info.exit.rval);
		}

		ptrace_wrap(PTRACE_SYSCALL, pid, NULL, 0);
		waitpid_wrap(pid, &status);
		
		if (WIFEXITED(status)) {
			fprintf(stderr, "+++ exited %i +++\n", WEXITSTATUS(status));
			break;
		}
	}
}

long ptrace_wrap(int op, ...) {
	long ret = ptrace(op);

	if (ret == -1) {
		perror("ptrace");
		exit(EXIT_FAILURE);
	}

	return ret;
}

void waitpid_wrap(pid_t pid, int *status) {
	if (waitpid(pid, status, 0) == -1) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
}

