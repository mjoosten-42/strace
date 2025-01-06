#include <signal.h>
#include <stdio.h>
#include <unistd.h>

sig_atomic_t flag = 0;

void handler(int signum) {
	flag = 1;
}

int main() {
	signal(SIGALRM, handler);
	alarm(1);

	while (1) {
		pause();

		if (flag) {
			flag = 0;
			alarm(1);
		}
	}
}

