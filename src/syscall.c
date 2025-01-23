#include "syscall.h"
#include "arch.h"

#include <stddef.h>

// TODO: calculate syscall_max
#define SYSCALL_MAX 548

static const t_syscall_prototype test[][SYSCALL_MAX] = {
	{
#include "32/prototypes.h"
	}, {
#include "64/prototypes.h"
	},
};

const t_syscall_prototype *syscall_get_prototype(e_arch arch, unsigned long nr) {
	const t_syscall_prototype *ret = NULL;

	if (nr < SYSCALL_MAX) {
		ret = &test[arch][nr];

		// Syscall gap
		if (!ret->name) {
			ret = NULL;
		}
	}

	return ret;
}

