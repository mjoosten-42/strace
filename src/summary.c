#include "summary.h"

#include "algorithm.h"
#include "arch.h"
#include "strace.h"

#include <linux/audit.h>
#include <locale.h>
#include <stdlib.h>
#include <time.h>

#define USECS 1000000L

// clang-format off
#define HEADER "% time     seconds  usecs/call     calls    errors syscall"
#define LINE   "------ ----------- ----------- --------- --------- ----------------"

// clang-format on

int was_called(void *p) {
	return ((count_t *)p)->calls;
}

void summarize(summary_t *summary) {
	int archs = 0;

	if (any(summary->count_64, SYSCALL_X86_64_MAX, sizeof(*summary->count_64), was_called)) {
		summarize_arch(summary->count_64, SYSCALL_X86_64_MAX, AUDIT_ARCH_X86_64);
		archs++;
	}

	if (any(summary->count_32, SYSCALL_I386_MAX, sizeof(*summary->count_32), was_called)) {
		if (archs) {
			eprintf("System call usage summary for 32 bit mode:\n");
		}

		summarize_arch(summary->count_32, SYSCALL_I386_MAX, AUDIT_ARCH_I386);
	}
}

void summarize_arch(count_t *array, int size, int arch) {
	count_t total  = { 0 };

	qsort(array, size, sizeof(*array), cmp);

	for (int i = 0; i < size; i++) {
		count_t count = array[i];

		tv_add(&total.time, &count.time);
		total.calls += count.calls;
		total.errors += count.errors;
	}

	eprintf("%s\n", HEADER);
	eprintf("%s\n", LINE);

	for (int i = 0; i < size; i++) {
		count_t count = array[i];

		if (count.calls) {
			print_count(&count, &total, arch);
		}
	}

	eprintf("%s\n", LINE);
	print_count(&total, &total, 0);
}

void print_count(count_t *count, count_t *total, int arch) {
	const t_syscall_prototype *prototype = syscall_get_prototype(arch, count->nr);
	struct timeval			   *time		 = &count->time;

	eprintf("%6.2f ", tv_div(time, &total->time) * 100.0f);
	eprintf("%11.6f ", (float)time->tv_sec + (float)time->tv_usec / (float)USECS);
	eprintf("%11lu ", (time->tv_sec * USECS + time->tv_usec) / count->calls);
	eprintf("%9i ", count->calls);

	if (count->errors) {
		eprintf("%9i ", count->errors);
	} else {
		eprintf("%9c ", ' ');
	}

	eprintf("%s", prototype ? prototype->name : "total");
	eprintf("\n");
}

void tv_add(struct timeval *first, struct timeval *second) {
	struct timeval out = { 0 };

	out.tv_sec	= first->tv_sec + second->tv_sec;
	out.tv_usec = first->tv_usec + second->tv_usec;

	if (out.tv_usec >= USECS) {
		out.tv_sec++;
		out.tv_usec -= USECS;
	}

	*first = out;
}

void tv_sub(struct timeval *first, struct timeval *second) {
	struct timeval out = { 0 };

	out.tv_sec = first->tv_sec - second->tv_sec;

	if (first->tv_usec >= second->tv_usec) {
		out.tv_usec = first->tv_usec - second->tv_usec;
	} else {
		out.tv_sec--;
		out.tv_usec = USECS - (second->tv_usec - first->tv_usec);
	}

	*first = out;
}

float tv_div(struct timeval *first, struct timeval *second) {
	float f = (float)(first->tv_sec * USECS + first->tv_usec);
	float g = (float)(second->tv_sec * USECS + second->tv_usec);

	return g ? f / g : f;
}

int cmp(const void *p, const void *q) {
	const count_t *f = p;
	const count_t *g = q;

	int ret = g->time.tv_sec - f->time.tv_sec;

	if (!ret) {
		ret = g->time.tv_usec - f->time.tv_usec;
	}

	return ret;
}
