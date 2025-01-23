#include <sys/mman.h>
#include <unistd.h>

int main() {
	void *p = mmap(NULL, getpagesize(), 0, 0, -1, 0);

	munmap(p, 4096);
}

