#include <signal.h>
#include <unistd.h>

int main() {
	kill(getpid(), SIGKILL); }
