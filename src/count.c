#include "strace.h"

#include <sys/time.h>

void count(pid_t pid, int status, int signalled) {
	static struct timeval start_time = { 0 };
	static int			  running	 = 0;

	// Ignore anything but syscall events
	if (signalled) {
		return;
	}

	struct timeval current = { 0 };

	CHECK_SYSCALL(gettimeofday(&current, NULL));

	if (!running) {
		start_time = current;
	} else {
		suseconds_t usec = (current.tv_sec - start_time.tv_sec) * 1000000 + current.tv_usec - start_time.tv_usec;

		eprintf("time: %lu\n", usec);
	}

	running = !running;

	(void)pid;
	(void)status;
}
