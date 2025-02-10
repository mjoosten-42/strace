#include "strace.h"

#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

const char *which(const char *filename) {
	struct stat buf = { 0 };

	if (strchr(filename, '/')) {
		if (stat(filename, &buf)) {
			return NULL;
		}

		return filename;
	}

	size_t		cap		= PATH_MAX;
	const char *paths	= getenv("PATH");
	char		 *path	= malloc(cap);
	size_t		filelen = strlen(filename);
	const char *colon	= NULL;

	if (!path || !paths) {
		return NULL;
	}

	while ((colon = strchr(paths, ':'))) {
		size_t dirlen = colon - paths;
		size_t len	  = dirlen + 1 + filelen;

		// Dynamically reallocate
		if (len + 1 > cap) {
			cap *= 2;
			path = realloc(path, cap);

			if (!path) {
				return NULL;
			}
		}

		strncpy(path, paths, dirlen);
		path[dirlen] = '/';
		strcpy(path + dirlen + 1, filename);

		// Check for executable bits
		if (!stat(path, &buf) && S_ISREG(buf.st_mode) && (buf.st_mode & 0111)) {
			return path;
		}

		paths = colon + 1;
	}

	free(path);

	return NULL;
}
