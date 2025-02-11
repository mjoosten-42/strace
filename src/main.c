#define _GNU_SOURCE

#include "opt.h"
#include "strace.h"
#include "summary.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

data_t data = { 0 };
opt_t  opt	= { 0 };

void handler(int signum) {
	data.interrupt = signum;
}

int main(int argc, char **argv) {
	const char *command = opts(argc, argv, &opt);
	const char *program = basename(argv[0]);

	if (!command) {
		eprintf("%s: must have PROG [ARGS]\n", program);
		return EXIT_FAILURE;
	}

	const char *path = which(command);

	if (!path) {
		eprintf("%s: Can't stat '%s': %s\n", program, command, strerror(errno));
		return EXIT_FAILURE;
	}

	CHECK_SYSCALL(data.pid = fork());

	if (!data.pid) {
		CHECK_SYSCALL(raise(SIGSTOP));
		CHECK_SYSCALL(execv(path, argv + optind));
	}

	struct sigaction sa = { .sa_handler = handler };
	CHECK_SYSCALL(sigaction(SIGINT, &sa, NULL));
	CHECK_SYSCALL(sigaction(SIGQUIT, &sa, NULL));
	CHECK_SYSCALL(sigaction(SIGTERM, &sa, NULL));

	CHECK_SYSCALL(ptrace(PTRACE_SEIZE, data.pid, NULL, PTRACE_O_TRACESYSGOOD));
	CHECK_SYSCALL(waitpid(data.pid, NULL, 0));

	return trace(&data, &opt);
}

const char *opts(int argc, char **argv, opt_t *opt) {
	const char *program	  = basename(argv[0]);
	const char *optstring = "cCh";
	int			c;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
			case 'C':
				opt->summary = 1;
				break;
			case 'c':
				opt->summary  = 1;
				opt->suppress = 1;
				break;
			case 'h':
				printf("usage: %s: [-%s] PROG [ARGS]\n", program, optstring);
				exit(EXIT_FAILURE);
			default:
				break;
		};
	}

	return argv[optind];
}
