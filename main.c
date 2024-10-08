#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
	printf("tracee args (%i):\n", argc);

	for (int i = 0; i < argc; i++) {
		printf("\t%s\n", argv[i]);	
	}

	return 0;
}
