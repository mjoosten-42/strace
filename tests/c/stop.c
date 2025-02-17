#include <sys/ptrace.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <time.h>

#define PTRACE_SEIZE_DEVEL	0x80000000

static const struct timespec ts1s = { .tv_sec = 1 };

int main(int argc, char **argv)
{
  pid_t tracee, tracer;
  int i;

  tracee = fork();
  if (!tracee)
	  while (1)
		  pause();

  tracer = fork();
  if (!tracer) {
	  siginfo_t si;

	  ptrace(PTRACE_SEIZE, tracee, NULL,
		 (void *)(unsigned long)PTRACE_SEIZE_DEVEL);
	  ptrace(PTRACE_INTERRUPT, tracee, NULL, NULL);
  repeat:
	  waitid(P_PID, tracee, NULL, WSTOPPED);

	  ptrace(PTRACE_GETSIGINFO, tracee, NULL, &si);
	  if (!si.si_code) {
		  printf("tracer: SIG %d\n", si.si_signo);
		  ptrace(PTRACE_CONT, tracee, NULL,
			 (void *)(unsigned long)si.si_signo);
		  goto repeat;
	  }
	  printf("tracer: stopped=%d signo=%d\n",
		 si.si_signo != SIGTRAP, si.si_signo);
	  if (si.si_signo != SIGTRAP)
		  ptrace(PTRACE_LISTEN, tracee, NULL, NULL);
	  else
		  ptrace(PTRACE_CONT, tracee, NULL, NULL);
	  goto repeat;
  }

  for (i = 0; i < 3; i++) {
	  nanosleep(&ts1s, NULL);
	  printf("mother: SIGSTOP\n");
	  kill(tracee, SIGSTOP);
	  nanosleep(&ts1s, NULL);
	  printf("mother: SIGCONT\n");
	  kill(tracee, SIGCONT);
  }
  nanosleep(&ts1s, NULL);

  kill(tracer, SIGKILL);
  kill(tracee, SIGKILL);
  return 0;
}
