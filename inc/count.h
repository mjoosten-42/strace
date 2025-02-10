#ifndef COUNT_H
#define COUNT_H

#include "arch.h"

#include <time.h>

typedef struct {
	int 		nr;
	int			calls;
	int			errors;
	struct timespec total;
} count_t;

typedef struct {
	count_t count_32[SYSCALL_X86_MAX];
	count_t count_64[SYSCALL_X86_64_MAX];
} counts_t;

void count(counts_t *counts);
void tv_add(struct timespec *first, struct timespec *second);
void tv_sub(struct timespec *first, struct timespec *second);
float tv_div(struct timespec *first, struct timespec *second);
int tv_cmp(const void *p, const void *q);

#endif
