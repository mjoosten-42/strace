#define _GNU_SOURCE

#include "strace.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char **argv) {
	pid_t pid = 0;

	if (argc < 2) {
		fprintf(stderr, "%s: must have PROG [ARGS]\n", argv[0]);
		return EXIT_FAILURE;
	}

	CHECK_SYSCALL(pid = fork());

	if (!pid) {
		CHECK_SYSCALL(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
		CHECK_SYSCALL(kill(getpid(), SIGSTOP));
		CHECK_SYSCALL(execvp(argv[1], argv + 1));
	}

	return trace(pid);
}
