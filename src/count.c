#include "strace.h"
#include "count.h"
#include "arch.h"
#include <stdlib.h>

#include <time.h>

#define NSECS 1000000000L
#define HEADER "% time     seconds  usecs/call     calls    errors syscall"
#define LINE   "------ ----------- ----------- --------- --------- ----------------"

void count(counts_t *counts) {
	qsort(counts->count_64, SYSCALL_X86_64_MAX, sizeof(count_t), tv_cmp);

	struct timespec total = { 0 };

	for (int i = 0; i < SYSCALL_X86_64_MAX; i++) {
		count_t count = counts->count_64[i];

		tv_add(&total, &count.total);
	}

	eprintf("%s\n", HEADER);
	eprintf("%s\n", LINE);

	for (int i = 0; i < SYSCALL_X86_64_MAX; i++) {
		count_t count = counts->count_64[i];

		if (!count.calls) {
			continue;
		}

		const t_syscall_prototype *prototype = syscall_get_prototype(X64, count.nr);
		struct timespec *time = &count.total;
		ssize_t usecs = (time->tv_sec * NSECS + time->tv_nsec) / 1000;

		eprintf("%6.2f ", tv_div(time, &total) * 100.0f);
		eprintf("%4li.%06li ", time->tv_sec, time->tv_nsec / 1000);		
		eprintf("%11lu ", usecs / count.calls);
		eprintf("%9i ", count.calls);

		if (count.errors) {
			eprintf("%9i ", count.errors);
		} else {
			eprintf("%9c ", ' ');
		}	

		eprintf("%s", prototype->name);
		eprintf("\n");
	}
	
	eprintf("%s\n", LINE);
	eprintf("100.00\n");
}

void tv_add(struct timespec *first, struct timespec *second) {
	struct timespec out = { 0 };

	out.tv_sec	 = first->tv_sec + second->tv_sec;
	out.tv_nsec = first->tv_nsec + second->tv_nsec;

	if (out.tv_nsec > NSECS) {
		out.tv_sec++;
		out.tv_nsec -= NSECS;
	}

	*first = out;
}

void tv_sub(struct timespec *first, struct timespec *second) {
	struct timespec out = { 0 };
	
	out.tv_sec = first->tv_sec - second->tv_sec;

	if (first->tv_nsec > second->tv_nsec) {
		out.tv_nsec = first->tv_nsec - second->tv_nsec;
	} else {
		out.tv_sec--;
		out.tv_nsec = NSECS - (second->tv_nsec - first->tv_nsec);
	}

	*first = out;
}

float tv_div(struct timespec *first, struct timespec *second) {
	return (float)(first->tv_sec * NSECS + first->tv_nsec) / (float)(second->tv_sec * NSECS + second->tv_nsec);
}

int tv_cmp(const void *p, const void *q) {
	struct timespec *f = (struct timespec *)p;
	struct timespec *g = (struct timespec *)q;

	if (f->tv_sec != g->tv_sec) {
		return f->tv_sec - g->tv_sec;
	}

	return f->tv_nsec - g->tv_nsec;
}
