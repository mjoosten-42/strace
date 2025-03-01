#ifndef COUNT_H
#define COUNT_H

#include "arch.h"

#include <sys/resource.h>
#include <time.h>

typedef struct {
	int			   nr;
	int			   calls;
	int			   errors;
	struct timeval time;
} count_t;

typedef struct {
	count_t count_64[SYSCALL_X86_64_MAX];
	count_t count_32[SYSCALL_I386_MAX];
} summary_t;

void summarize(summary_t *counts);
void summarize_arch(count_t *array, int size, int arch);

void print_count(count_t *count, count_t *total, int arch);

void  tv_add(struct timeval *first, struct timeval *second);
void  tv_sub(struct timeval *first, struct timeval *second);
float tv_div(struct timeval *first, struct timeval *second);

int cmp(const void *p, const void *q);

#endif
