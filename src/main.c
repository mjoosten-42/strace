#define _GNU_SOURCE

#include "opt.h"
#include "strace.h"

#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char **argv) {
	const char *program = basename(argv[0]);
	opt_t opt = { 0 };
	pid_t pid;
	int c;

	while ((c = getopt(argc, argv, "chT")) != -1) {
		switch (c) {
			case 'c':
				opt.summary = 1;
				break;
			case 'h':
				printf("usage: %s: [-chT] PROG [ARGS]\n", program);
				return EXIT_FAILURE;
			case 'T':
				opt.time = 1;
				break;
			default:
				break;
		};
	}

	if (opt.time && opt.summary) {
		eprintf("%s: -T has no effect with -c\n", program);
	}

	const char *command = argv[optind];

	if (!command) {
		eprintf("%s: must have PROG [ARGS]\n", program);
		return EXIT_FAILURE;
	}

	const char *path = which(command);

	if (!path) {
		eprintf("%s: Can't stat '%s': %s\n", program, command, strerror(errno));
		return EXIT_FAILURE;
	}

	CHECK_SYSCALL(pid = fork());

	if (!pid) {
		CHECK_SYSCALL(raise(SIGSTOP));
		CHECK_SYSCALL(execv(path, argv + optind));
	}

	CHECK_SYSCALL(ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD));
	CHECK_SYSCALL(waitpid(pid, NULL, 0));

	return trace(pid, &opt);
}
