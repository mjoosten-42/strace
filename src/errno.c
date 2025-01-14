#define _GNU_SOURCE

#include <string.h>

#ifndef ERESTARTSYS
	#define ERESTARTSYS 512
#endif
#ifndef ERESTARTNOINTR
	#define ERESTARTNOINTR 513
#endif
#ifndef ERESTARTNOHAND
	#define ERESTARTNOHAND 514
#endif
#ifndef ERESTART_RESTARTBLOCK
	#define ERESTART_RESTARTBLOCK 516
#endif

const char *strerrorname(int error) {
	static const char *errors[] = {
		"ERESTARTSYS",
		"ERESTARTNOINTR",
		"ERESTARTNOHAND",
		"ERESTART_RESTARTBLOCK",
	};

	switch (error) {
		case ERESTARTSYS:
			return errors[0];
		case ERESTARTNOINTR:
			return errors[1];
		case ERESTARTNOHAND:
			return errors[2];
		case ERESTART_RESTARTBLOCK:
			return errors[3];
		default:
			return strerrorname_np(error);
	}
}

const char *strerrordesc(int error) {
	static const char *descs[] = {
		"To be restarted if SA_RESTART is set",
		"To be restarted",
		"To be restarted if no handler",
		"Interrupted by signal",
	};

	switch (error) {
		case ERESTARTSYS:
			return descs[0];
		case ERESTARTNOINTR:
			return descs[1];
		case ERESTARTNOHAND:
			return descs[2];
		case ERESTART_RESTARTBLOCK:
			return descs[3];
		default:
			return strerror(error);
	}
}
