#define _GNU_SOURCE

#include "strace.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
	pid_t pid = 0;

	if (argc < 2) {
		fprintf(stderr, "%s: must have PROG [ARGS]\n", argv[0]);
		return EXIT_FAILURE;
	}

	/*
	struct stat statbuf = { 0 };
	int ret = stat(argv[1], &statbuf);

	if (ret == -1) {
		fprintf(stderr, "%s: can't stat %s: %s\n", argv[0], argv[1],
	strerror(errno));
		//return EXIT_FAILURE;
	}
	*/

	CHECK_SYSCALL(pid = fork());

	if (!pid) {
		CHECK_SYSCALL(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
		CHECK_SYSCALL(kill(getpid(), SIGSTOP));
		CHECK_SYSCALL(execve(argv[1], argv + 1, envp));
	}

	trace(pid);
}
