#define _GNU_SOURCE

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char **argv) {
	if ((long)setlocale(LC_ALL, "") == -1) {
		fprintf(stderr, "%s: %s: %s\n", basename(argv[0]), "setlocale", strerror(errno));
	}
}
