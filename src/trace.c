#define _GNU_SOURCE // strerrorname_np

#include "strace.h"
#include "syscall.h"

#include <stdio.h>		// fprintf
#include <stdlib.h>		// exit
#include <string.h>		// strerror
#include <sys/ptrace.h> // ptrace
#include <sys/wait.h>	// waitpid

void trace(pid_t pid) {
	t_syscall_info info	  = { 0 };
	int			   status = 0;

	CHECK_SYSCALL(waitpid(pid, &status, 0));
	CHECK_SYSCALL(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD));

	while (1) {
		CHECK_SYSCALL(ptrace(PTRACE_SYSCALL, pid, NULL, NULL));
		CHECK_SYSCALL(waitpid(pid, &status, 0));

		if (WIFEXITED(status)) {
			on_tracee_exit(&info, status);
			break;
		}

		CHECK_SYSCALL(ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info.values), &info.values));

		if (info.values.op == PTRACE_SYSCALL_INFO_ENTRY) {
			on_syscall_start(&info);
		}

		if (info.values.op == PTRACE_SYSCALL_INFO_EXIT) {
			on_syscall_end(&info);
		}
	}
}

void on_syscall_start(t_syscall_info *info) {
	info->prototype = syscall_get_prototype(info->values.entry.nr);

	fprintf(stderr, "%s(", info->prototype->name);

	for (int i = 0; i < info->prototype->argc; i++) {
		fprintf(stderr, info->prototype->args[i].format, info->values.entry.args[i]);

		if (i < info->prototype->argc - 1) {
			fprintf(stderr, ", ");
		}
	}

	fprintf(stderr, ") = ");

	info->running = 1;
}

void on_syscall_end(t_syscall_info *info) {
	int ret = info->values.exit.rval;

	if (ret < 0) {
		const char *errname = strerrorname_np(-ret);
		const char *errmsg	= strerror(-ret);

		fprintf(stderr, "%i %s (%s)", -1, errname, errmsg);
	} else {
		fprintf(stderr, info->prototype->ret.format, ret);
	}

	fprintf(stderr, "\n");

	info->running = 0;
}

void on_tracee_exit(t_syscall_info *info, int status) {
	if (info->running) {
		fprintf(stderr, "?\n");
	}

	fprintf(stderr, "+++ exited with %i +++\n", WEXITSTATUS(status));
}
