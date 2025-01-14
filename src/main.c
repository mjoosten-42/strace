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

	CHECK_SYSCALL(pid = fork());

	if (!pid) {
		// TODO: path search before kill
		CHECK_SYSCALL(kill(getpid(), SIGSTOP));
		CHECK_SYSCALL(execvp(argv[1], argv + 1));
	}

	CHECK_SYSCALL(ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD));

	return trace(pid);
}
