#include <unistd.h>
#include <errno.h>

int main() {
	for (int i = 0; errno != EBADF; i++) {
		isatty(i);
	}
}
