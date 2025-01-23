#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>

int main() {
	struct rlimit limit = { 0 };

	getrlimit(RLIMIT_NOFILE, &limit);

	limit.rlim_cur = limit.rlim_max;

	setrlimit(RLIMIT_NOFILE, &limit);

	for (int i = 0;; i++) {
		if (dup(1) == -1) {
			fprintf(stderr, "[%d] dup: %s\n", i, strerror(errno));
			break;
		}
	}
}

