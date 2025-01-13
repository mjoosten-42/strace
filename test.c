#define _GNU_SOURCE

#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

void f(int signum) {
	printf("strsignal: %s\n", strsignal(signum));
	psignal(signum, "psignal message");
	printf("sigdescr_np: %s\n", sigdescr_np(signum));
	printf("sigabbrev_np: %s\n", sigabbrev_np(signum));
}

int main() {
	signal(SIGQUIT, f);
	kill(getpid(), SIGQUIT);
	pause();
}
