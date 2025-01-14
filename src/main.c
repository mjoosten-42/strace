#define _GNU_SOURCE

#include "strace.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char **argv) {
	pid_t pid = 0;

	if (argc < 2) {
		eprintf("%s: must have PROG [ARGS]\n", argv[0]);
		return EXIT_FAILURE;
	}

	const char *path = which(argv[1]);

	if (!path) {
		return EXIT_FAILURE;
	}

	CHECK_SYSCALL(pid = fork());

	if (!pid) {
		CHECK_SYSCALL(kill(getpid(), SIGSTOP));
		CHECK_SYSCALL(execv(path, argv + 1));
	}

	CHECK_SYSCALL(ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD));

	return trace(pid);
}
