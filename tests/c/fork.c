#define _GNU_SOURCE

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>

#define AMOUNT (1024 * 1024 * 1024)

void f(int signum, siginfo_t *info, void *context) {
	(void)signum;
	(void)context;

	printf("CLOCKS_PER_SEC: %li\n", CLOCKS_PER_SEC);
	printf("utime: %li, %li\n", info->si_utime, info->si_utime * CLOCKS_PER_SEC);
	printf("stime: %li, %li\n", info->si_stime, info->si_stime * CLOCKS_PER_SEC);
}

void do_sys(char *buf) {
	for (int i = 0; i < 2; i++) {
		int fd = open("/dev/random", 0);
		
		read(fd, buf, AMOUNT);
	}
}

void do_user(char *buf) {
	for (size_t i = 0; i < AMOUNT; i++) {
		buf[i] = buf[i] * buf[i];
	}
}

size_t factorial(size_t n) {
	if (!n) {
		return 1;
	}

	return n * factorial(n - 1);
}

int main(int argc, char **argv) {
	pid_t pid	  = 0;
	int status = 0;
	char *buf = malloc(AMOUNT);

	struct sigaction sa = { .sa_sigaction = f, .sa_flags = SA_SIGINFO };

	//sigaction(SIGCHLD, &sa, NULL);

	pid = fork();

	if (!pid) {
		do_sys(buf);
		do_user(buf);
		exit(0);
	}

	waitpid(pid, &status, 0);
}
