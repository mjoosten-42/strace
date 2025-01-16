#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <string.h>

void f(int signum) {
	printf("Received SIG%s\n", sigabbrev_np(signum));
}

int main() {
	struct sigaction sa = { 0 };

	sa.sa_handler = f;

	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	
	while (1) {
		alarm(1);
		pause();
	}
}
