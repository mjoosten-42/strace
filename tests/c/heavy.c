#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define MB (1024 * 1024UL)
#define AMOUNT (128 * MB)
#define LOOPS 16

size_t sum(int fd, char *buf, size_t bufsize);

int main() {
	int fd = open("/dev/random", 0);
	char *buf = malloc(AMOUNT);
	
	if (!buf) {
		perror("malloc");
		exit(1);
	}

	printf("0\r");

	for (size_t i = 0; i < LOOPS; i++) {
		printf("\r%lu",	sum(fd, buf, AMOUNT));
	}

	printf("\n");
	free(buf);
}

size_t sum(int fd, char *buf, size_t bufsize) {
	size_t total = 0;
	ssize_t bytes = read(fd, buf, bufsize);

	if (bytes == -1) {
		perror("read");
		exit(1);
	}

	for (char *c = buf; c < buf + bytes; c++) {
		total += *c;
	}

	return total;
}
