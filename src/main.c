#include "strace.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {

	if (argc < 2) {
		fprintf(stderr, "%s: must have PROG [ARGS]\n", argv[0]);
		return EXIT_FAILURE;
	}

	pid_t pid = fork();

	switch (pid) {
		case -1:
			perror("fork");
			return EXIT_FAILURE;
		case 0:
			ptrace_wrap(PTRACE_TRACEME);
			execve(argv[1], argv + 1, envp);
			perror("execve");
			return EXIT_FAILURE;
		default:
			trace(pid);
	}

	return 0;
}
