#include "algorithm.h"

int any(void *array, size_t count, size_t size, int (*f)(void *)) {
	char *ptr = array;

	for (size_t i = 0; i < count; i++) {
		if (f(ptr + (i * size))) {
			return 1;
		}
	}

	return 0;
}
