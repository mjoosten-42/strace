#ifndef ALGORITHM_H
#define ALGORITHM_H

#include <stddef.h>

int any(void *array, size_t count, size_t size, int (*f)(void *));

#endif
