#include "strace.h"

#include <time.h>

void count(pid_t pid, int status, int signalled) {
	static struct timespec start = { 0 };
	static int			  running	 = 0;

	// Ignore anything but syscall events
	if (signalled) {
		return;
	}

	struct timespec current = { 0 };

	CHECK_SYSCALL(clock_gettime(CLOCK_MONOTONIC, &current));

	if (!running) {
		start = current;
	} else {
		eprintf("time: %li\n", current.tv_sec - start.tv_sec); // TODO
	}

	running = !running;

	(void)pid;
	(void)status;
}

