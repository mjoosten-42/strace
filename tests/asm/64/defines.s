%define poll 7
%define brk 12
%define sigaction 13
%define sigprocmask 14
%define sigreturn 15
%define pause 34
%define nanosleep 35
%define alarm 37
%define getpid 39
%define execve 59
%define exit 60
%define kill 62
%define uselib 134
%define landlock_add_rule 445
%define pwrite2 447
%define process_mrelease 448
%define removexattrat 466

%define SIGINT 2
%define SIGQUIT 3
%define SIGTRAP 5
%define SIGKILL 9
%define SIGALRM 14
%define SIGTERM 15
%define SIGCHLD 17
%define SIGCONT 18
%define SIGSTOP 19
%define SIGTSTP 20
%define SIGTTIN 21
%define SIGTTOU 22

%define SA_RESTORER 0x04000000

%define SIG_BLOCK 0 

%define SIG_DFL	0
%define SIG_IGN	1
%define SIG_ERR	-1
