#include "syscall.h"

#include "arch.h"

#include <linux/audit.h>
#include <stddef.h>

static const t_syscall_prototype i386[SYSCALL_I386_MAX] = {
#include "32/prototypes.h"
};

static const t_syscall_prototype x86_64[SYSCALL_X86_64_MAX] = {
#include "64/prototypes.h"
};

const t_syscall_prototype *syscall_get_prototype(int arch, int nr) {
	const t_syscall_prototype *ret = NULL;

	if (arch & __AUDIT_ARCH_64BIT) {
		if (nr >= SYSCALL_X86_64_MAX) {
			return NULL;
		}

		ret = &x86_64[nr];
	} else {
		if (nr >= SYSCALL_I386_MAX) {
			return NULL;
		}

		ret = &i386[nr];
	}

	return ret;
}

const char *get_format(enum e_type type) {
	const char *formats[] = {
		"%i", "%u", "%li", "%lu", "%p",
		"%i", // Enum
	};

	return formats[type];
}
