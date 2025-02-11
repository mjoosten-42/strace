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
	count_t count_32[SYSCALL_X86_MAX];
	count_t count_64[SYSCALL_X86_64_MAX];
} summary_t;

void summarize(summary_t *counts);
void summarize_arch(count_t *array, int size, e_arch arch);

void  tv_add(struct timeval *first, struct timeval *second);
void  tv_sub(struct timeval *first, struct timeval *second);
float tv_div(struct timeval *first, struct timeval *second);
int	  tv_cmp(const void *p, const void *q);

#endif
