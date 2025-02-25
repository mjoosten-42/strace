#define _GNU_SOURCE

#include "opt.h"
#include "strace.h"
#include "summary.h"

#include <errno.h>
#include <linux/audit.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

data_t data = { .arch = AUDIT_ARCH_X86_64 };
opt_t  opt	= { 0 };

int			interrupt = 0;
const char *program;

int main(int argc, char **argv, char **envp) {
	EXIT_IF_FAILED(setlocale(LC_ALL, ""));

	program = basename(argv[0]);

	const char *command = opts(argc, argv, &opt);

	if (!command) {
		eprintf("%s: must have PROG [ARGS]\n", program);
		return EXIT_FAILURE;
	}

	const char *path = which(command);

	if (!path) {
		eprintf("%s: Can't stat '%s': %s\n", program, command, strerror(errno));
		return EXIT_FAILURE;
	}

	EXIT_IF_FAILED(data.pid = fork());

	if (!data.pid) {
		EXIT_IF_FAILED(raise(SIGSTOP));
		EXIT_IF_FAILED(execve(path, argv + optind, envp));
		exit(EXIT_FAILURE);
	}

	// Buffer stderr to reduce write() calls
	// Syscall-start is flushed manually
	EXIT_IF_FAILED(setvbuf(stderr, NULL, _IOLBF, 0));

	// Allow printing summary when terminated
	struct sigaction sa = { .sa_handler = handler };
	EXIT_IF_FAILED(sigaction(SIGINT, &sa, NULL));
	EXIT_IF_FAILED(sigaction(SIGQUIT, &sa, NULL));
	EXIT_IF_FAILED(sigaction(SIGTERM, &sa, NULL));

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

void handler(int signum) {
	interrupt = signum;
}
