#ifndef COUNT_H
#define COUNT_H

#include "arch.h"

#include <time.h>

typedef struct {
	size_t			calls;
	size_t			errors;
	struct timespec total;
} count_t;

typedef struct {
	count_t count_32[SYSCALL_X86_MAX];
	count_t count_64[SYSCALL_X86_64_MAX];
} counts_t;

#endif
