#include <signal.h>
#include <unistd.h>

void handler(int signum) { (void)signum; }

int main() {
	while (1) {
		signal(SIGALRM, handler);
		alarm(1);
		pause();
	}
}

