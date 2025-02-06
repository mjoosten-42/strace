#include "strace.h"

#include <time.h>

void tv_add(struct timespec *out, struct timespec *first, struct timespec *second) {
	out->tv_sec	 = first->tv_sec + second->tv_sec;
	out->tv_nsec = first->tv_nsec + second->tv_nsec;

	if (out->tv_nsec > 1000000000) {
		out->tv_sec++;
		out->tv_nsec -= 1000000000;
	}
}

void tv_sub(struct timespec *out, struct timespec *first, struct timespec *second) {
	out->tv_sec = first->tv_sec - second->tv_sec;

	if (first->tv_nsec > second->tv_nsec) {
		out->tv_nsec = first->tv_nsec - second->tv_nsec;
	} else {
		out->tv_sec--;
		out->tv_nsec = 1000000000 - (second->tv_nsec - first->tv_nsec);
	}
}
