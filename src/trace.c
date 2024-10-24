#include "strace.h"
#include "syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

void trace(pid_t pid) {
	struct __ptrace_syscall_info info			 = { 0 };
	int							 status			 = 0;
	int							 syscall_started = 0;

	waitpid(pid, &status, 0);
	ptrace_wrap(PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_O_TRACESYSGOOD);

	while (1) {
		ptrace_wrap(PTRACE_SYSCALL, pid, NULL, NULL); // restart tracee
		waitpid_wrap(pid, &status);					  // block tracer

		if (WIFEXITED(status)) {
			if (syscall_started) {
				fprintf(stderr, "?\n");
			}

			fprintf(stderr, "+++ exited with %i +++\n", WEXITSTATUS(status));
			break;
		}

		ptrace_wrap(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info);

		const syscall_info *sys_info = get_syscall_info(info.entry.nr);

		if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
			fprintf(stderr, "%s(", sys_info->name);
			
			for (int i = 0; i < sys_info->argc; i++) {
				fprintf(stderr, sys_info->args[i].format, info.entry.args[i]);
				
				if (i < sys_info->argc - 1) {
					fprintf(stderr, ", ");
				}
			}

			fprintf(stderr, ") = ");

			syscall_started = 1;
		}

		if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
			fprintf(stderr, "%li\n", info.exit.rval);
			syscall_started = 0;
		}
	}
}

long ptrace_wrap(int op, pid_t pid, void *addr, void *data) {
	long ret = ptrace(op, pid, addr, data);

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
