#define _GNU_SOURCE // strerrorname_np

#include "strace.h"
#include "syscall.h"

#include <stdio.h>		// fprintf
#include <stdlib.h>		// exit
#include <string.h>		// strerror
#include <sys/ptrace.h> // ptrace
#include <sys/wait.h>	// waitpid

void trace(pid_t pid) {
	const syscall_info		   *sys_info = NULL;
	struct __ptrace_syscall_info info	  = { 0 };
	int							 status	  = 0;

	waitpid(pid, &status, 0);
	ptrace_wrap(PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_O_TRACESYSGOOD);

	while (1) {
		ptrace_wrap(PTRACE_SYSCALL, pid, NULL, NULL); // restart tracee
		waitpid_wrap(pid, &status);					  // block tracer

		if (WIFEXITED(status)) {
			if (sys_info) {
				fprintf(stderr, "?\n");
			}

			fprintf(stderr, "+++ exited with %i +++\n", WEXITSTATUS(status));
			break;
		}

		ptrace_wrap(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info);

		if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
			sys_info = get_syscall_info(info.entry.nr);

			fprintf(stderr, "%s(", sys_info->name);

			for (int i = 0; i < sys_info->argc; i++) {
				fprintf(stderr, sys_info->args[i].format, info.entry.args[i]);

				if (i < sys_info->argc - 1) {
					fprintf(stderr, ", ");
				}
			}

			fprintf(stderr, ") = ");
		}

		if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
			int ret = info.exit.rval;

			if (ret < 0) {
				const char *errname = strerrorname_np(-ret);
				const char *errmsg	= strerror(-ret);

				fprintf(stderr, "%i %s (%s)", -1, errname, errmsg);
			} else {
				fprintf(stderr, sys_info->ret.format, ret);
			}

			fprintf(stderr, "\n");

			sys_info = NULL;
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
