#include "syscall.h"

const syscall_info *get_syscall_info(int nr) {
	static const syscall_info syscalls[] = {
		{ 0, "read", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "char *buf", "%s", 8 },	
		{ "size_t count", "%lu", 8 },	
		} },
		{ 1, "write", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "const char *buf", "%s", 8 },	
		{ "size_t count", "%lu", 8 },	
		} },
		{ 2, "open", 3, { 
		{ "const char *filename", "%s", 8 },	
		{ "int flags", "%i", 4 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 3, "close", 1, { 
		{ "unsigned int fd", "%i", 4 },	
		} },
		{ 4, "stat", 2, { 
		{ "const char *filename", "%s", 8 },	
		{ "struct __old_kernel_stat *statbuf", "%p", 8 },	
		} },
		{ 5, "fstat", 2, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "struct __old_kernel_stat *statbuf", "%p", 8 },	
		} },
		{ 6, "lstat", 2, { 
		{ "const char *filename", "%s", 8 },	
		{ "struct __old_kernel_stat *statbuf", "%p", 8 },	
		} },
		{ 7, "poll", 3, { 
		{ "struct pollfd *ufds", "%p", 8 },	
		{ "unsigned int nfds", "%i", 4 },	
		{ "int timeout", "%i", 4 },	
		} },
		{ 8, "lseek", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "off_t offset", "%lu", 8 },	
		{ "unsigned int whence", "%i", 4 },	
		} },
		{ 9, "mmap", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 10, "mprotect", 3, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "unsigned long prot", "%lu", 8 },	
		} },
		{ 11, "munmap", 2, { 
		{ "unsigned long addr", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		} },
		{ 12, "brk", 1, { 
		{ "unsigned long brk", "%lu", 8 },	
		} },
		{ 13, "rt_sigaction", 4, { 
		{ "int", "%i", 4 },	
		{ "const struct sigaction *", "%p", 8 },	
		{ "struct sigaction *", "%p", 8 },	
		{ "size_t", "%lu", 8 },	
		} },
		{ 14, "rt_sigprocmask", 4, { 
		{ "int how", "%i", 4 },	
		{ "sigset_t *set", "%p", 8 },	
		{ "sigset_t *oset", "%p", 8 },	
		{ "size_t sigsetsize", "%lu", 8 },	
		} },
		{ 15, "rt_sigreturn", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 16, "ioctl", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "unsigned int cmd", "%i", 4 },	
		{ "unsigned long arg", "%lu", 8 },	
		} },
		{ 17, "pread64", 4, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "char *buf", "%s", 8 },	
		{ "size_t count", "%lu", 8 },	
		{ "loff_t pos", "%lu", 8 },	
		} },
		{ 18, "pwrite64", 4, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "const char *buf", "%s", 8 },	
		{ "size_t count", "%lu", 8 },	
		{ "loff_t pos", "%lu", 8 },	
		} },
		{ 19, "readv", 3, { 
		{ "unsigned long fd", "%lu", 8 },	
		{ "const struct iovec *vec", "%p", 8 },	
		{ "unsigned long vlen", "%lu", 8 },	
		} },
		{ 20, "writev", 3, { 
		{ "unsigned long fd", "%lu", 8 },	
		{ "const struct iovec *vec", "%p", 8 },	
		{ "unsigned long vlen", "%lu", 8 },	
		} },
		{ 21, "access", 2, { 
		{ "const char *filename", "%s", 8 },	
		{ "int mode", "%i", 4 },	
		} },
		{ 22, "pipe", 1, { 
		{ "int *fildes", "%p", 8 },	
		} },
		{ 23, "select", 5, { 
		{ "int n", "%i", 4 },	
		{ "fd_set *inp", "%p", 8 },	
		{ "fd_set *outp", "%p", 8 },	
		{ "fd_set *exp", "%p", 8 },	
		{ "struct timeval *tvp", "%p", 8 },	
		} },
		{ 24, "sched_yield", 0, { 
		} },
		{ 25, "mremap", 5, { 
		{ "unsigned long addr", "%lu", 8 },	
		{ "unsigned long old_len", "%lu", 8 },	
		{ "unsigned long new_len", "%lu", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		{ "unsigned long new_addr", "%lu", 8 },	
		} },
		{ 26, "msync", 3, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 27, "mincore", 3, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "unsigned char * vec", "%s", 8 },	
		} },
		{ 28, "madvise", 3, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "int behavior", "%i", 4 },	
		} },
		{ 29, "shmget", 3, { 
		{ "key_t key", "%lu", 8 },	
		{ "size_t size", "%lu", 8 },	
		{ "int flag", "%i", 4 },	
		} },
		{ 30, "shmat", 3, { 
		{ "int shmid", "%i", 4 },	
		{ "char *shmaddr", "%s", 8 },	
		{ "int shmflg", "%i", 4 },	
		} },
		{ 31, "shmctl", 3, { 
		{ "int shmid", "%i", 4 },	
		{ "int cmd", "%i", 4 },	
		{ "struct shmid_ds *buf", "%p", 8 },	
		} },
		{ 32, "dup", 1, { 
		{ "unsigned int fildes", "%i", 4 },	
		} },
		{ 33, "dup2", 2, { 
		{ "unsigned int oldfd", "%i", 4 },	
		{ "unsigned int newfd", "%i", 4 },	
		} },
		{ 34, "pause", 0, { 
		} },
		{ 35, "nanosleep", 2, { 
		{ "struct __kernel_timespec *rqtp", "%p", 8 },	
		{ "struct __kernel_timespec *rmtp", "%p", 8 },	
		} },
		{ 36, "getitimer", 2, { 
		{ "int which", "%i", 4 },	
		{ "struct itimerval *value", "%p", 8 },	
		} },
		{ 37, "alarm", 1, { 
		{ "unsigned int seconds", "%i", 4 },	
		} },
		{ 38, "setitimer", 3, { 
		{ "int which", "%i", 4 },	
		{ "struct itimerval *value", "%p", 8 },	
		{ "struct itimerval *ovalue", "%p", 8 },	
		} },
		{ 39, "getpid", 0, { 
		} },
		{ 40, "sendfile", 4, { 
		{ "int out_fd", "%i", 4 },	
		{ "int in_fd", "%i", 4 },	
		{ "off_t *offset", "%p", 8 },	
		{ "size_t count", "%lu", 8 },	
		} },
		{ 41, "socket", 3, { 
		{ "int", "%i", 4 },	
		{ "int", "%i", 4 },	
		{ "int", "%i", 4 },	
		} },
		{ 42, "connect", 3, { 
		{ "int", "%i", 4 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int", "%i", 4 },	
		} },
		{ 43, "accept", 3, { 
		{ "int", "%i", 4 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int *", "%p", 8 },	
		} },
		{ 44, "sendto", 6, { 
		{ "int", "%i", 4 },	
		{ "void *", "%p", 8 },	
		{ "size_t", "%lu", 8 },	
		{ "unsigned", "%lu", 8 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int", "%i", 4 },	
		} },
		{ 45, "recvfrom", 6, { 
		{ "int", "%i", 4 },	
		{ "void *", "%p", 8 },	
		{ "size_t", "%lu", 8 },	
		{ "unsigned", "%lu", 8 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int *", "%p", 8 },	
		} },
		{ 46, "sendmsg", 3, { 
		{ "int fd", "%i", 4 },	
		{ "struct user_msghdr *msg", "%p", 8 },	
		{ "unsigned flags", "%lu", 8 },	
		} },
		{ 47, "recvmsg", 3, { 
		{ "int fd", "%i", 4 },	
		{ "struct user_msghdr *msg", "%p", 8 },	
		{ "unsigned flags", "%lu", 8 },	
		} },
		{ 48, "shutdown", 2, { 
		{ "int", "%i", 4 },	
		{ "int", "%i", 4 },	
		} },
		{ 49, "bind", 3, { 
		{ "int", "%i", 4 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int", "%i", 4 },	
		} },
		{ 50, "listen", 2, { 
		{ "int", "%i", 4 },	
		{ "int", "%i", 4 },	
		} },
		{ 51, "getsockname", 3, { 
		{ "int", "%i", 4 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int *", "%p", 8 },	
		} },
		{ 52, "getpeername", 3, { 
		{ "int", "%i", 4 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int *", "%p", 8 },	
		} },
		{ 53, "socketpair", 4, { 
		{ "int", "%i", 4 },	
		{ "int", "%i", 4 },	
		{ "int", "%i", 4 },	
		{ "int *", "%p", 8 },	
		} },
		{ 54, "setsockopt", 5, { 
		{ "int fd", "%i", 4 },	
		{ "int level", "%i", 4 },	
		{ "int optname", "%i", 4 },	
		{ "char *optval", "%s", 8 },	
		{ "int optlen", "%i", 4 },	
		} },
		{ 55, "getsockopt", 5, { 
		{ "int fd", "%i", 4 },	
		{ "int level", "%i", 4 },	
		{ "int optname", "%i", 4 },	
		{ "char *optval", "%s", 8 },	
		{ "int *optlen", "%p", 8 },	
		} },
		{ 56, "clone", 5, { 
		{ "unsigned long", "%lu", 8 },	
		{ "unsigned long", "%lu", 8 },	
		{ "int *", "%p", 8 },	
		{ "int *", "%p", 8 },	
		{ "unsigned long", "%lu", 8 },	
		} },
		{ 57, "fork", 0, { 
		} },
		{ 58, "vfork", 0, { 
		} },
		{ 59, "execve", 3, { 
		{ "const char *filename", "%s", 8 },	
		{ "const char *const *argv", "%p", 8 },	
		{ "const char *const *envp", "%p", 8 },	
		} },
		{ 60, "exit", 1, { 
		{ "int error_code", "%i", 4 },	
		} },
		{ 61, "wait4", 4, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "int *stat_addr", "%p", 8 },	
		{ "int options", "%i", 4 },	
		{ "struct rusage *ru", "%p", 8 },	
		} },
		{ 62, "kill", 2, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "int sig", "%i", 4 },	
		} },
		{ 63, "uname", 1, { 
		{ "struct old_utsname *", "%p", 8 },	
		} },
		{ 64, "semget", 3, { 
		{ "key_t key", "%lu", 8 },	
		{ "int nsems", "%i", 4 },	
		{ "int semflg", "%i", 4 },	
		} },
		{ 65, "semop", 3, { 
		{ "int semid", "%i", 4 },	
		{ "struct sembuf *sops", "%p", 8 },	
		{ "unsigned nsops", "%lu", 8 },	
		} },
		{ 66, "semctl", 4, { 
		{ "int semid", "%i", 4 },	
		{ "int semnum", "%i", 4 },	
		{ "int cmd", "%i", 4 },	
		{ "unsigned long arg", "%lu", 8 },	
		} },
		{ 67, "shmdt", 1, { 
		{ "char *shmaddr", "%s", 8 },	
		} },
		{ 68, "msgget", 2, { 
		{ "key_t key", "%lu", 8 },	
		{ "int msgflg", "%i", 4 },	
		} },
		{ 69, "msgsnd", 4, { 
		{ "int msqid", "%i", 4 },	
		{ "struct msgbuf *msgp", "%p", 8 },	
		{ "size_t msgsz", "%lu", 8 },	
		{ "int msgflg", "%i", 4 },	
		} },
		{ 70, "msgrcv", 5, { 
		{ "int msqid", "%i", 4 },	
		{ "struct msgbuf *msgp", "%p", 8 },	
		{ "size_t msgsz", "%lu", 8 },	
		{ "long msgtyp", "%lu", 8 },	
		{ "int msgflg", "%i", 4 },	
		} },
		{ 71, "msgctl", 3, { 
		{ "int msqid", "%i", 4 },	
		{ "int cmd", "%i", 4 },	
		{ "struct msqid_ds *buf", "%p", 8 },	
		} },
		{ 72, "fcntl", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "unsigned int cmd", "%i", 4 },	
		{ "unsigned long arg", "%lu", 8 },	
		} },
		{ 73, "flock", 2, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "unsigned int cmd", "%i", 4 },	
		} },
		{ 74, "fsync", 1, { 
		{ "unsigned int fd", "%i", 4 },	
		} },
		{ 75, "fdatasync", 1, { 
		{ "unsigned int fd", "%i", 4 },	
		} },
		{ 76, "truncate", 2, { 
		{ "const char *path", "%s", 8 },	
		{ "long length", "%lu", 8 },	
		} },
		{ 77, "ftruncate", 2, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "unsigned long length", "%lu", 8 },	
		} },
		{ 78, "getdents", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "struct linux_dirent *dirent", "%p", 8 },	
		{ "unsigned int count", "%i", 4 },	
		} },
		{ 79, "getcwd", 2, { 
		{ "char *buf", "%s", 8 },	
		{ "unsigned long size", "%lu", 8 },	
		} },
		{ 80, "chdir", 1, { 
		{ "const char *filename", "%s", 8 },	
		} },
		{ 81, "fchdir", 1, { 
		{ "unsigned int fd", "%i", 4 },	
		} },
		{ 82, "rename", 2, { 
		{ "const char *oldname", "%s", 8 },	
		{ "const char *newname", "%s", 8 },	
		} },
		{ 83, "mkdir", 2, { 
		{ "const char *pathname", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 84, "rmdir", 1, { 
		{ "const char *pathname", "%s", 8 },	
		} },
		{ 85, "creat", 2, { 
		{ "const char *pathname", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 86, "link", 2, { 
		{ "const char *oldname", "%s", 8 },	
		{ "const char *newname", "%s", 8 },	
		} },
		{ 87, "unlink", 1, { 
		{ "const char *pathname", "%s", 8 },	
		} },
		{ 88, "symlink", 2, { 
		{ "const char *old", "%s", 8 },	
		{ "const char *new", "%s", 8 },	
		} },
		{ 89, "readlink", 3, { 
		{ "const char *path", "%s", 8 },	
		{ "char *buf", "%s", 8 },	
		{ "int bufsiz", "%i", 4 },	
		} },
		{ 90, "chmod", 2, { 
		{ "const char *filename", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 91, "fchmod", 2, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 92, "chown", 3, { 
		{ "const char *filename", "%s", 8 },	
		{ "uid_t user", "%lu", 8 },	
		{ "gid_t group", "%lu", 8 },	
		} },
		{ 93, "fchown", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "uid_t user", "%lu", 8 },	
		{ "gid_t group", "%lu", 8 },	
		} },
		{ 94, "lchown", 3, { 
		{ "const char *filename", "%s", 8 },	
		{ "uid_t user", "%lu", 8 },	
		{ "gid_t group", "%lu", 8 },	
		} },
		{ 95, "umask", 1, { 
		{ "int mask", "%i", 4 },	
		} },
		{ 96, "gettimeofday", 2, { 
		{ "struct timeval *tv", "%p", 8 },	
		{ "struct timezone *tz", "%p", 8 },	
		} },
		{ 97, "getrlimit", 2, { 
		{ "unsigned int resource", "%i", 4 },	
		{ "struct rlimit *rlim", "%p", 8 },	
		} },
		{ 98, "getrusage", 2, { 
		{ "int who", "%i", 4 },	
		{ "struct rusage *ru", "%p", 8 },	
		} },
		{ 99, "sysinfo", 1, { 
		{ "struct sysinfo *info", "%p", 8 },	
		} },
		{ 100, "times", 1, { 
		{ "struct tms *tbuf", "%p", 8 },	
		} },
		{ 101, "ptrace", 4, { 
		{ "long request", "%lu", 8 },	
		{ "long pid", "%lu", 8 },	
		{ "unsigned long addr", "%lu", 8 },	
		{ "unsigned long data", "%lu", 8 },	
		} },
		{ 102, "getuid", 0, { 
		} },
		{ 103, "syslog", 3, { 
		{ "int type", "%i", 4 },	
		{ "char *buf", "%s", 8 },	
		{ "int len", "%i", 4 },	
		} },
		{ 104, "getgid", 0, { 
		} },
		{ 105, "setuid", 1, { 
		{ "uid_t uid", "%lu", 8 },	
		} },
		{ 106, "setgid", 1, { 
		{ "gid_t gid", "%lu", 8 },	
		} },
		{ 107, "geteuid", 0, { 
		} },
		{ 108, "getegid", 0, { 
		} },
		{ 109, "setpgid", 2, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "pid_t pgid", "%lu", 8 },	
		} },
		{ 110, "getppid", 0, { 
		} },
		{ 111, "getpgrp", 0, { 
		} },
		{ 112, "setsid", 0, { 
		} },
		{ 113, "setreuid", 2, { 
		{ "uid_t ruid", "%lu", 8 },	
		{ "uid_t euid", "%lu", 8 },	
		} },
		{ 114, "setregid", 2, { 
		{ "gid_t rgid", "%lu", 8 },	
		{ "gid_t egid", "%lu", 8 },	
		} },
		{ 115, "getgroups", 2, { 
		{ "int gidsetsize", "%i", 4 },	
		{ "gid_t *grouplist", "%p", 8 },	
		} },
		{ 116, "setgroups", 2, { 
		{ "int gidsetsize", "%i", 4 },	
		{ "gid_t *grouplist", "%p", 8 },	
		} },
		{ 117, "setresuid", 3, { 
		{ "uid_t ruid", "%lu", 8 },	
		{ "uid_t euid", "%lu", 8 },	
		{ "uid_t suid", "%lu", 8 },	
		} },
		{ 118, "getresuid", 3, { 
		{ "uid_t *ruid", "%p", 8 },	
		{ "uid_t *euid", "%p", 8 },	
		{ "uid_t *suid", "%p", 8 },	
		} },
		{ 119, "setresgid", 3, { 
		{ "gid_t rgid", "%lu", 8 },	
		{ "gid_t egid", "%lu", 8 },	
		{ "gid_t sgid", "%lu", 8 },	
		} },
		{ 120, "getresgid", 3, { 
		{ "gid_t *rgid", "%p", 8 },	
		{ "gid_t *egid", "%p", 8 },	
		{ "gid_t *sgid", "%p", 8 },	
		} },
		{ 121, "getpgid", 1, { 
		{ "pid_t pid", "%lu", 8 },	
		} },
		{ 122, "setfsuid", 1, { 
		{ "uid_t uid", "%lu", 8 },	
		} },
		{ 123, "setfsgid", 1, { 
		{ "gid_t gid", "%lu", 8 },	
		} },
		{ 124, "getsid", 1, { 
		{ "pid_t pid", "%lu", 8 },	
		} },
		{ 125, "capget", 2, { 
		{ "cap_user_header_t header", "%lu", 8 },	
		{ "cap_user_data_t dataptr", "%lu", 8 },	
		} },
		{ 126, "capset", 2, { 
		{ "cap_user_header_t header", "%lu", 8 },	
		{ "const cap_user_data_t data", "%lu", 8 },	
		} },
		{ 127, "rt_sigpending", 2, { 
		{ "sigset_t *set", "%p", 8 },	
		{ "size_t sigsetsize", "%lu", 8 },	
		} },
		{ 128, "rt_sigtimedwait", 4, { 
		{ "const sigset_t *uthese", "%p", 8 },	
		{ "siginfo_t *uinfo", "%p", 8 },	
		{ "const struct __kernel_timespec *uts", "%p", 8 },	
		{ "size_t sigsetsize", "%lu", 8 },	
		} },
		{ 129, "rt_sigqueueinfo", 3, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "int sig", "%i", 4 },	
		{ "siginfo_t *uinfo", "%p", 8 },	
		} },
		{ 130, "rt_sigsuspend", 2, { 
		{ "sigset_t *unewset", "%p", 8 },	
		{ "size_t sigsetsize", "%lu", 8 },	
		} },
		{ 131, "sigaltstack", 2, { 
		{ "const struct sigaltstack *uss", "%p", 8 },	
		{ "struct sigaltstack *uoss", "%p", 8 },	
		} },
		{ 132, "utime", 2, { 
		{ "char *filename", "%s", 8 },	
		{ "struct utimbuf *times", "%p", 8 },	
		} },
		{ 133, "mknod", 3, { 
		{ "const char *filename", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		{ "unsigned dev", "%lu", 8 },	
		} },
		{ 134, "uselib", 1, { 
		{ "const char *library", "%s", 8 },	
		} },
		{ 135, "personality", 1, { 
		{ "unsigned int personality", "%i", 4 },	
		} },
		{ 136, "ustat", 2, { 
		{ "unsigned dev", "%lu", 8 },	
		{ "struct ustat *ubuf", "%p", 8 },	
		} },
		{ 137, "statfs", 2, { 
		{ "const char * path", "%s", 8 },	
		{ "struct statfs *buf", "%p", 8 },	
		} },
		{ 138, "fstatfs", 2, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "struct statfs *buf", "%p", 8 },	
		} },
		{ 139, "sysfs", 3, { 
		{ "int option", "%i", 4 },	
		{ "unsigned long arg1", "%lu", 8 },	
		{ "unsigned long arg2", "%lu", 8 },	
		} },
		{ 140, "getpriority", 2, { 
		{ "int which", "%i", 4 },	
		{ "int who", "%i", 4 },	
		} },
		{ 141, "setpriority", 3, { 
		{ "int which", "%i", 4 },	
		{ "int who", "%i", 4 },	
		{ "int niceval", "%i", 4 },	
		} },
		{ 142, "sched_setparam", 2, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "struct sched_param *param", "%p", 8 },	
		} },
		{ 143, "sched_getparam", 2, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "struct sched_param *param", "%p", 8 },	
		} },
		{ 144, "sched_setscheduler", 3, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "int policy", "%i", 4 },	
		{ "struct sched_param *param", "%p", 8 },	
		} },
		{ 145, "sched_getscheduler", 1, { 
		{ "pid_t pid", "%lu", 8 },	
		} },
		{ 146, "sched_get_priority_max", 1, { 
		{ "int policy", "%i", 4 },	
		} },
		{ 147, "sched_get_priority_min", 1, { 
		{ "int policy", "%i", 4 },	
		} },
		{ 148, "sched_rr_get_interval", 2, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "struct __kernel_timespec *interval", "%p", 8 },	
		} },
		{ 149, "mlock", 2, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		} },
		{ 150, "munlock", 2, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		} },
		{ 151, "mlockall", 1, { 
		{ "int flags", "%i", 4 },	
		} },
		{ 152, "munlockall", 0, { 
		} },
		{ 153, "vhangup", 0, { 
		} },
		{ 154, "modify_ldt", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 155, "pivot_root", 2, { 
		{ "const char *new_root", "%s", 8 },	
		{ "const char *put_old", "%s", 8 },	
		} },
		{ 156, "_sysctl", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 157, "prctl", 5, { 
		{ "int option", "%i", 4 },	
		{ "unsigned long arg2", "%lu", 8 },	
		{ "unsigned long arg3", "%lu", 8 },	
		{ "unsigned long arg4", "%lu", 8 },	
		{ "unsigned long arg5", "%lu", 8 },	
		} },
		{ 158, "arch_prctl", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 159, "adjtimex", 1, { 
		{ "struct __kernel_timex *txc_p", "%p", 8 },	
		} },
		{ 160, "setrlimit", 2, { 
		{ "unsigned int resource", "%i", 4 },	
		{ "struct rlimit *rlim", "%p", 8 },	
		} },
		{ 161, "chroot", 1, { 
		{ "const char *filename", "%s", 8 },	
		} },
		{ 162, "sync", 0, { 
		} },
		{ 163, "acct", 1, { 
		{ "const char *name", "%s", 8 },	
		} },
		{ 164, "settimeofday", 2, { 
		{ "struct timeval *tv", "%p", 8 },	
		{ "struct timezone *tz", "%p", 8 },	
		} },
		{ 165, "mount", 5, { 
		{ "char *dev_name", "%s", 8 },	
		{ "char *dir_name", "%s", 8 },	
		{ "char *type", "%s", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		{ "void *data", "%p", 8 },	
		} },
		{ 166, "umount2", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 167, "swapon", 2, { 
		{ "const char *specialfile", "%s", 8 },	
		{ "int swap_flags", "%i", 4 },	
		} },
		{ 168, "swapoff", 1, { 
		{ "const char *specialfile", "%s", 8 },	
		} },
		{ 169, "reboot", 4, { 
		{ "int magic1", "%i", 4 },	
		{ "int magic2", "%i", 4 },	
		{ "unsigned int cmd", "%i", 4 },	
		{ "void *arg", "%p", 8 },	
		} },
		{ 170, "sethostname", 2, { 
		{ "char *name", "%s", 8 },	
		{ "int len", "%i", 4 },	
		} },
		{ 171, "setdomainname", 2, { 
		{ "char *name", "%s", 8 },	
		{ "int len", "%i", 4 },	
		} },
		{ 172, "iopl", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 173, "ioperm", 3, { 
		{ "unsigned long from", "%lu", 8 },	
		{ "unsigned long num", "%lu", 8 },	
		{ "int on", "%i", 4 },	
		} },
		{ 174, "create_module", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 175, "init_module", 3, { 
		{ "void *umod", "%p", 8 },	
		{ "unsigned long len", "%lu", 8 },	
		{ "const char *uargs", "%s", 8 },	
		} },
		{ 176, "delete_module", 2, { 
		{ "const char *name_user", "%s", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 177, "get_kernel_syms", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 178, "query_module", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 179, "quotactl", 4, { 
		{ "unsigned int cmd", "%i", 4 },	
		{ "const char *special", "%s", 8 },	
		{ "qid_t id", "%lu", 8 },	
		{ "void *addr", "%p", 8 },	
		} },
		{ 180, "nfsservctl", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 181, "getpmsg", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 182, "putpmsg", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 183, "afs_syscall", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 184, "tuxcall", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 185, "security", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 186, "gettid", 0, { 
		} },
		{ 187, "readahead", 3, { 
		{ "int fd", "%i", 4 },	
		{ "loff_t offset", "%lu", 8 },	
		{ "size_t count", "%lu", 8 },	
		} },
		{ 188, "setxattr", 5, { 
		{ "const char *path", "%s", 8 },	
		{ "const char *name", "%s", 8 },	
		{ "const void *value", "%p", 8 },	
		{ "size_t size", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 189, "lsetxattr", 5, { 
		{ "const char *path", "%s", 8 },	
		{ "const char *name", "%s", 8 },	
		{ "const void *value", "%p", 8 },	
		{ "size_t size", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 190, "fsetxattr", 5, { 
		{ "int fd", "%i", 4 },	
		{ "const char *name", "%s", 8 },	
		{ "const void *value", "%p", 8 },	
		{ "size_t size", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 191, "getxattr", 4, { 
		{ "const char *path", "%s", 8 },	
		{ "const char *name", "%s", 8 },	
		{ "void *value", "%p", 8 },	
		{ "size_t size", "%lu", 8 },	
		} },
		{ 192, "lgetxattr", 4, { 
		{ "const char *path", "%s", 8 },	
		{ "const char *name", "%s", 8 },	
		{ "void *value", "%p", 8 },	
		{ "size_t size", "%lu", 8 },	
		} },
		{ 193, "fgetxattr", 4, { 
		{ "int fd", "%i", 4 },	
		{ "const char *name", "%s", 8 },	
		{ "void *value", "%p", 8 },	
		{ "size_t size", "%lu", 8 },	
		} },
		{ 194, "listxattr", 3, { 
		{ "const char *path", "%s", 8 },	
		{ "char *list", "%s", 8 },	
		{ "size_t size", "%lu", 8 },	
		} },
		{ 195, "llistxattr", 3, { 
		{ "const char *path", "%s", 8 },	
		{ "char *list", "%s", 8 },	
		{ "size_t size", "%lu", 8 },	
		} },
		{ 196, "flistxattr", 3, { 
		{ "int fd", "%i", 4 },	
		{ "char *list", "%s", 8 },	
		{ "size_t size", "%lu", 8 },	
		} },
		{ 197, "removexattr", 2, { 
		{ "const char *path", "%s", 8 },	
		{ "const char *name", "%s", 8 },	
		} },
		{ 198, "lremovexattr", 2, { 
		{ "const char *path", "%s", 8 },	
		{ "const char *name", "%s", 8 },	
		} },
		{ 199, "fremovexattr", 2, { 
		{ "int fd", "%i", 4 },	
		{ "const char *name", "%s", 8 },	
		} },
		{ 200, "tkill", 2, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "int sig", "%i", 4 },	
		} },
		{ 201, "time", 1, { 
		{ "time_t *tloc", "%p", 8 },	
		} },
		{ 202, "futex", 6, { 
		{ "u32 *uaddr", "%p", 8 },	
		{ "int op", "%i", 4 },	
		{ "u32 val", "%lu", 8 },	
		{ "struct __kernel_timespec *utime", "%p", 8 },	
		{ "u32 *uaddr2", "%p", 8 },	
		{ "u32 val3", "%lu", 8 },	
		} },
		{ 203, "sched_setaffinity", 3, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "unsigned int len", "%i", 4 },	
		{ "unsigned long *user_mask_ptr", "%p", 8 },	
		} },
		{ 204, "sched_getaffinity", 3, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "unsigned int len", "%i", 4 },	
		{ "unsigned long *user_mask_ptr", "%p", 8 },	
		} },
		{ 205, "set_thread_area", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 206, "io_setup", 2, { 
		{ "unsigned nr_reqs", "%lu", 8 },	
		{ "aio_context_t *ctx", "%p", 8 },	
		} },
		{ 207, "io_destroy", 1, { 
		{ "aio_context_t ctx", "%lu", 8 },	
		} },
		{ 208, "io_getevents", 5, { 
		{ "aio_context_t ctx_id", "%lu", 8 },	
		{ "long min_nr", "%lu", 8 },	
		{ "long nr", "%lu", 8 },	
		{ "struct io_event *events", "%p", 8 },	
		{ "struct __kernel_timespec *timeout", "%p", 8 },	
		} },
		{ 209, "io_submit", 3, { 
		{ "aio_context_t", "%lu", 8 },	
		{ "long", "%lu", 8 },	
		{ "struct iocb * *", "%p", 8 },	
		} },
		{ 210, "io_cancel", 3, { 
		{ "aio_context_t ctx_id", "%lu", 8 },	
		{ "struct iocb *iocb", "%p", 8 },	
		{ "struct io_event *result", "%p", 8 },	
		} },
		{ 211, "get_thread_area", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 212, "lookup_dcookie", 3, { 
		{ "u64 cookie64", "%lu", 8 },	
		{ "char *buf", "%s", 8 },	
		{ "size_t len", "%lu", 8 },	
		} },
		{ 213, "epoll_create", 1, { 
		{ "int size", "%i", 4 },	
		} },
		{ 214, "epoll_ctl_old", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 215, "epoll_wait_old", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 216, "remap_file_pages", 5, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "unsigned long size", "%lu", 8 },	
		{ "unsigned long prot", "%lu", 8 },	
		{ "unsigned long pgoff", "%lu", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 217, "getdents64", 3, { 
		{ "unsigned int fd", "%i", 4 },	
		{ "struct linux_dirent64 *dirent", "%p", 8 },	
		{ "unsigned int count", "%i", 4 },	
		} },
		{ 218, "set_tid_address", 1, { 
		{ "int *tidptr", "%p", 8 },	
		} },
		{ 219, "restart_syscall", 0, { 
		} },
		{ 220, "semtimedop", 4, { 
		{ "int semid", "%i", 4 },	
		{ "struct sembuf *sops", "%p", 8 },	
		{ "unsigned nsops", "%lu", 8 },	
		{ "const struct __kernel_timespec *timeout", "%p", 8 },	
		} },
		{ 221, "fadvise64", 4, { 
		{ "int fd", "%i", 4 },	
		{ "loff_t offset", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "int advice", "%i", 4 },	
		} },
		{ 222, "timer_create", 3, { 
		{ "clockid_t which_clock", "%lu", 8 },	
		{ "struct sigevent *timer_event_spec", "%p", 8 },	
		{ "timer_t * created_timer_id", "%p", 8 },	
		} },
		{ 223, "timer_settime", 4, { 
		{ "timer_t timer_id", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		{ "const struct __kernel_itimerspec *new_setting", "%p", 8 },	
		{ "struct __kernel_itimerspec *old_setting", "%p", 8 },	
		} },
		{ 224, "timer_gettime", 2, { 
		{ "timer_t timer_id", "%lu", 8 },	
		{ "struct __kernel_itimerspec *setting", "%p", 8 },	
		} },
		{ 225, "timer_getoverrun", 1, { 
		{ "timer_t timer_id", "%lu", 8 },	
		} },
		{ 226, "timer_delete", 1, { 
		{ "timer_t timer_id", "%lu", 8 },	
		} },
		{ 227, "clock_settime", 2, { 
		{ "clockid_t which_clock", "%lu", 8 },	
		{ "const struct __kernel_timespec *tp", "%p", 8 },	
		} },
		{ 228, "clock_gettime", 2, { 
		{ "clockid_t which_clock", "%lu", 8 },	
		{ "struct __kernel_timespec *tp", "%p", 8 },	
		} },
		{ 229, "clock_getres", 2, { 
		{ "clockid_t which_clock", "%lu", 8 },	
		{ "struct __kernel_timespec *tp", "%p", 8 },	
		} },
		{ 230, "clock_nanosleep", 4, { 
		{ "clockid_t which_clock", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		{ "const struct __kernel_timespec *rqtp", "%p", 8 },	
		{ "struct __kernel_timespec *rmtp", "%p", 8 },	
		} },
		{ 231, "exit_group", 1, { 
		{ "int error_code", "%i", 4 },	
		} },
		{ 232, "epoll_wait", 4, { 
		{ "int epfd", "%i", 4 },	
		{ "struct epoll_event *events", "%p", 8 },	
		{ "int maxevents", "%i", 4 },	
		{ "int timeout", "%i", 4 },	
		} },
		{ 233, "epoll_ctl", 4, { 
		{ "int epfd", "%i", 4 },	
		{ "int op", "%i", 4 },	
		{ "int fd", "%i", 4 },	
		{ "struct epoll_event *event", "%p", 8 },	
		} },
		{ 234, "tgkill", 3, { 
		{ "pid_t tgid", "%lu", 8 },	
		{ "pid_t pid", "%lu", 8 },	
		{ "int sig", "%i", 4 },	
		} },
		{ 235, "utimes", 2, { 
		{ "char *filename", "%s", 8 },	
		{ "struct timeval *utimes", "%p", 8 },	
		} },
		{ 236, "vserver", 6, { 
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		{ "?", "%lu", 8 },	
		} },
		{ 237, "mbind", 6, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "unsigned long len", "%lu", 8 },	
		{ "unsigned long mode", "%lu", 8 },	
		{ "const unsigned long *nmask", "%p", 8 },	
		{ "unsigned long maxnode", "%lu", 8 },	
		{ "unsigned flags", "%lu", 8 },	
		} },
		{ 238, "set_mempolicy", 3, { 
		{ "int mode", "%i", 4 },	
		{ "const unsigned long *nmask", "%p", 8 },	
		{ "unsigned long maxnode", "%lu", 8 },	
		} },
		{ 239, "get_mempolicy", 5, { 
		{ "int *policy", "%p", 8 },	
		{ "unsigned long *nmask", "%p", 8 },	
		{ "unsigned long maxnode", "%lu", 8 },	
		{ "unsigned long addr", "%lu", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 240, "mq_open", 4, { 
		{ "const char *name", "%s", 8 },	
		{ "int oflag", "%i", 4 },	
		{ "umode_t mode", "%lu", 8 },	
		{ "struct mq_attr *attr", "%p", 8 },	
		} },
		{ 241, "mq_unlink", 1, { 
		{ "const char *name", "%s", 8 },	
		} },
		{ 242, "mq_timedsend", 5, { 
		{ "mqd_t mqdes", "%lu", 8 },	
		{ "const char *msg_ptr", "%s", 8 },	
		{ "size_t msg_len", "%lu", 8 },	
		{ "unsigned int msg_prio", "%i", 4 },	
		{ "const struct __kernel_timespec *abs_timeout", "%p", 8 },	
		} },
		{ 243, "mq_timedreceive", 5, { 
		{ "mqd_t mqdes", "%lu", 8 },	
		{ "char *msg_ptr", "%s", 8 },	
		{ "size_t msg_len", "%lu", 8 },	
		{ "unsigned int *msg_prio", "%p", 8 },	
		{ "const struct __kernel_timespec *abs_timeout", "%p", 8 },	
		} },
		{ 244, "mq_notify", 2, { 
		{ "mqd_t mqdes", "%lu", 8 },	
		{ "const struct sigevent *notification", "%p", 8 },	
		} },
		{ 245, "mq_getsetattr", 3, { 
		{ "mqd_t mqdes", "%lu", 8 },	
		{ "const struct mq_attr *mqstat", "%p", 8 },	
		{ "struct mq_attr *omqstat", "%p", 8 },	
		} },
		{ 246, "kexec_load", 4, { 
		{ "unsigned long entry", "%lu", 8 },	
		{ "unsigned long nr_segments", "%lu", 8 },	
		{ "struct kexec_segment *segments", "%p", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 247, "waitid", 5, { 
		{ "int which", "%i", 4 },	
		{ "pid_t pid", "%lu", 8 },	
		{ "struct siginfo *infop", "%p", 8 },	
		{ "int options", "%i", 4 },	
		{ "struct rusage *ru", "%p", 8 },	
		} },
		{ 248, "add_key", 5, { 
		{ "const char *_type", "%s", 8 },	
		{ "const char *_description", "%s", 8 },	
		{ "const void *_payload", "%p", 8 },	
		{ "size_t plen", "%lu", 8 },	
		{ "key_serial_t destringid", "%lu", 8 },	
		} },
		{ 249, "request_key", 4, { 
		{ "const char *_type", "%s", 8 },	
		{ "const char *_description", "%s", 8 },	
		{ "const char *_callout_info", "%s", 8 },	
		{ "key_serial_t destringid", "%lu", 8 },	
		} },
		{ 250, "keyctl", 5, { 
		{ "int cmd", "%i", 4 },	
		{ "unsigned long arg2", "%lu", 8 },	
		{ "unsigned long arg3", "%lu", 8 },	
		{ "unsigned long arg4", "%lu", 8 },	
		{ "unsigned long arg5", "%lu", 8 },	
		} },
		{ 251, "ioprio_set", 3, { 
		{ "int which", "%i", 4 },	
		{ "int who", "%i", 4 },	
		{ "int ioprio", "%i", 4 },	
		} },
		{ 252, "ioprio_get", 2, { 
		{ "int which", "%i", 4 },	
		{ "int who", "%i", 4 },	
		} },
		{ 253, "inotify_init", 0, { 
		} },
		{ 254, "inotify_add_watch", 3, { 
		{ "int fd", "%i", 4 },	
		{ "const char *path", "%s", 8 },	
		{ "u32 mask", "%lu", 8 },	
		} },
		{ 255, "inotify_rm_watch", 2, { 
		{ "int fd", "%i", 4 },	
		{ "__s32 wd", "%lu", 8 },	
		} },
		{ 256, "migrate_pages", 4, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "unsigned long maxnode", "%lu", 8 },	
		{ "const unsigned long *from", "%p", 8 },	
		{ "const unsigned long *to", "%p", 8 },	
		} },
		{ 257, "openat", 4, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "int flags", "%i", 4 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 258, "mkdirat", 3, { 
		{ "int dfd", "%i", 4 },	
		{ "const char * pathname", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 259, "mknodat", 4, { 
		{ "int dfd", "%i", 4 },	
		{ "const char * filename", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		{ "unsigned dev", "%lu", 8 },	
		} },
		{ 260, "fchownat", 5, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "uid_t user", "%lu", 8 },	
		{ "gid_t group", "%lu", 8 },	
		{ "int flag", "%i", 4 },	
		} },
		{ 261, "futimesat", 3, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "struct timeval *utimes", "%p", 8 },	
		} },
		{ 262, "newfstatat", 4, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "struct stat *statbuf", "%p", 8 },	
		{ "int flag", "%i", 4 },	
		} },
		{ 263, "unlinkat", 3, { 
		{ "int dfd", "%i", 4 },	
		{ "const char * pathname", "%s", 8 },	
		{ "int flag", "%i", 4 },	
		} },
		{ 264, "renameat", 4, { 
		{ "int olddfd", "%i", 4 },	
		{ "const char * oldname", "%s", 8 },	
		{ "int newdfd", "%i", 4 },	
		{ "const char * newname", "%s", 8 },	
		} },
		{ 265, "linkat", 5, { 
		{ "int olddfd", "%i", 4 },	
		{ "const char *oldname", "%s", 8 },	
		{ "int newdfd", "%i", 4 },	
		{ "const char *newname", "%s", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 266, "symlinkat", 3, { 
		{ "const char * oldname", "%s", 8 },	
		{ "int newdfd", "%i", 4 },	
		{ "const char * newname", "%s", 8 },	
		} },
		{ 267, "readlinkat", 4, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *path", "%s", 8 },	
		{ "char *buf", "%s", 8 },	
		{ "int bufsiz", "%i", 4 },	
		} },
		{ 268, "fchmodat", 3, { 
		{ "int dfd", "%i", 4 },	
		{ "const char * filename", "%s", 8 },	
		{ "umode_t mode", "%lu", 8 },	
		} },
		{ 269, "faccessat", 3, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "int mode", "%i", 4 },	
		} },
		{ 270, "pselect6", 6, { 
		{ "int", "%i", 4 },	
		{ "fd_set *", "%p", 8 },	
		{ "fd_set *", "%p", 8 },	
		{ "fd_set *", "%p", 8 },	
		{ "struct __kernel_timespec *", "%p", 8 },	
		{ "void *", "%p", 8 },	
		} },
		{ 271, "ppoll", 5, { 
		{ "struct pollfd *", "%p", 8 },	
		{ "unsigned int", "%i", 4 },	
		{ "struct __kernel_timespec *", "%p", 8 },	
		{ "const sigset_t *", "%p", 8 },	
		{ "size_t", "%lu", 8 },	
		} },
		{ 272, "unshare", 1, { 
		{ "unsigned long unshare_flags", "%lu", 8 },	
		} },
		{ 273, "set_robust_list", 2, { 
		{ "struct robust_list_head *head", "%p", 8 },	
		{ "size_t len", "%lu", 8 },	
		} },
		{ 274, "get_robust_list", 3, { 
		{ "int pid", "%i", 4 },	
		{ "struct robust_list_head * *head_ptr", "%p", 8 },	
		{ "size_t *len_ptr", "%p", 8 },	
		} },
		{ 275, "splice", 6, { 
		{ "int fd_in", "%i", 4 },	
		{ "loff_t *off_in", "%p", 8 },	
		{ "int fd_out", "%i", 4 },	
		{ "loff_t *off_out", "%p", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 276, "tee", 4, { 
		{ "int fdin", "%i", 4 },	
		{ "int fdout", "%i", 4 },	
		{ "size_t len", "%lu", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 277, "sync_file_range", 4, { 
		{ "int fd", "%i", 4 },	
		{ "loff_t offset", "%lu", 8 },	
		{ "loff_t nbytes", "%lu", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 278, "vmsplice", 4, { 
		{ "int fd", "%i", 4 },	
		{ "const struct iovec *iov", "%p", 8 },	
		{ "unsigned long nr_segs", "%lu", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 279, "move_pages", 6, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "unsigned long nr_pages", "%lu", 8 },	
		{ "const void * *pages", "%p", 8 },	
		{ "const int *nodes", "%p", 8 },	
		{ "int *status", "%p", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 280, "utimensat", 4, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "struct __kernel_timespec *utimes", "%p", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 281, "epoll_pwait", 6, { 
		{ "int epfd", "%i", 4 },	
		{ "struct epoll_event *events", "%p", 8 },	
		{ "int maxevents", "%i", 4 },	
		{ "int timeout", "%i", 4 },	
		{ "const sigset_t *sigmask", "%p", 8 },	
		{ "size_t sigsetsize", "%lu", 8 },	
		} },
		{ 282, "signalfd", 3, { 
		{ "int ufd", "%i", 4 },	
		{ "sigset_t *user_mask", "%p", 8 },	
		{ "size_t sizemask", "%lu", 8 },	
		} },
		{ 283, "timerfd_create", 2, { 
		{ "int clockid", "%i", 4 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 284, "eventfd", 1, { 
		{ "unsigned int count", "%i", 4 },	
		} },
		{ 285, "fallocate", 4, { 
		{ "int fd", "%i", 4 },	
		{ "int mode", "%i", 4 },	
		{ "loff_t offset", "%lu", 8 },	
		{ "loff_t len", "%lu", 8 },	
		} },
		{ 286, "timerfd_settime", 4, { 
		{ "int ufd", "%i", 4 },	
		{ "int flags", "%i", 4 },	
		{ "const struct __kernel_itimerspec *utmr", "%p", 8 },	
		{ "struct __kernel_itimerspec *otmr", "%p", 8 },	
		} },
		{ 287, "timerfd_gettime", 2, { 
		{ "int ufd", "%i", 4 },	
		{ "struct __kernel_itimerspec *otmr", "%p", 8 },	
		} },
		{ 288, "accept4", 4, { 
		{ "int", "%i", 4 },	
		{ "struct sockaddr *", "%p", 8 },	
		{ "int *", "%p", 8 },	
		{ "int", "%i", 4 },	
		} },
		{ 289, "signalfd4", 4, { 
		{ "int ufd", "%i", 4 },	
		{ "sigset_t *user_mask", "%p", 8 },	
		{ "size_t sizemask", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 290, "eventfd2", 2, { 
		{ "unsigned int count", "%i", 4 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 291, "epoll_create1", 1, { 
		{ "int flags", "%i", 4 },	
		} },
		{ 292, "dup3", 3, { 
		{ "unsigned int oldfd", "%i", 4 },	
		{ "unsigned int newfd", "%i", 4 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 293, "pipe2", 2, { 
		{ "int *fildes", "%p", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 294, "inotify_init1", 1, { 
		{ "int flags", "%i", 4 },	
		} },
		{ 295, "preadv", 5, { 
		{ "unsigned long fd", "%lu", 8 },	
		{ "const struct iovec *vec", "%p", 8 },	
		{ "unsigned long vlen", "%lu", 8 },	
		{ "unsigned long pos_l", "%lu", 8 },	
		{ "unsigned long pos_h", "%lu", 8 },	
		} },
		{ 296, "pwritev", 5, { 
		{ "unsigned long fd", "%lu", 8 },	
		{ "const struct iovec *vec", "%p", 8 },	
		{ "unsigned long vlen", "%lu", 8 },	
		{ "unsigned long pos_l", "%lu", 8 },	
		{ "unsigned long pos_h", "%lu", 8 },	
		} },
		{ 297, "rt_tgsigqueueinfo", 4, { 
		{ "pid_t tgid", "%lu", 8 },	
		{ "pid_t pid", "%lu", 8 },	
		{ "int sig", "%i", 4 },	
		{ "siginfo_t *uinfo", "%p", 8 },	
		} },
		{ 298, "perf_event_open", 5, { 
		{ "struct perf_event_attr *attr_uptr", "%p", 8 },	
		{ "pid_t pid", "%lu", 8 },	
		{ "int cpu", "%i", 4 },	
		{ "int group_fd", "%i", 4 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 299, "recvmmsg", 5, { 
		{ "int fd", "%i", 4 },	
		{ "struct mmsghdr *msg", "%p", 8 },	
		{ "unsigned int vlen", "%i", 4 },	
		{ "unsigned flags", "%lu", 8 },	
		{ "struct __kernel_timespec *timeout", "%p", 8 },	
		} },
		{ 300, "fanotify_init", 2, { 
		{ "unsigned int flags", "%i", 4 },	
		{ "unsigned int event_f_flags", "%i", 4 },	
		} },
		{ 301, "fanotify_mark", 5, { 
		{ "int fanotify_fd", "%i", 4 },	
		{ "unsigned int flags", "%i", 4 },	
		{ "u64 mask", "%lu", 8 },	
		{ "int fd", "%i", 4 },	
		{ "const char *pathname", "%s", 8 },	
		} },
		{ 302, "prlimit64", 4, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "unsigned int resource", "%i", 4 },	
		{ "const struct rlimit64 *new_rlim", "%p", 8 },	
		{ "struct rlimit64 *old_rlim", "%p", 8 },	
		} },
		{ 303, "name_to_handle_at", 5, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *name", "%s", 8 },	
		{ "struct file_handle *handle", "%p", 8 },	
		{ "int *mnt_id", "%p", 8 },	
		{ "int flag", "%i", 4 },	
		} },
		{ 304, "open_by_handle_at", 3, { 
		{ "int mountdirfd", "%i", 4 },	
		{ "struct file_handle *handle", "%p", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 305, "clock_adjtime", 2, { 
		{ "clockid_t which_clock", "%lu", 8 },	
		{ "struct __kernel_timex *tx", "%p", 8 },	
		} },
		{ 306, "syncfs", 1, { 
		{ "int fd", "%i", 4 },	
		} },
		{ 307, "sendmmsg", 4, { 
		{ "int fd", "%i", 4 },	
		{ "struct mmsghdr *msg", "%p", 8 },	
		{ "unsigned int vlen", "%i", 4 },	
		{ "unsigned flags", "%lu", 8 },	
		} },
		{ 308, "setns", 2, { 
		{ "int fd", "%i", 4 },	
		{ "int nstype", "%i", 4 },	
		} },
		{ 309, "getcpu", 3, { 
		{ "unsigned *cpu", "%p", 8 },	
		{ "unsigned *node", "%p", 8 },	
		{ "struct getcpu_cache *cache", "%p", 8 },	
		} },
		{ 310, "process_vm_readv", 6, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "const struct iovec *lvec", "%p", 8 },	
		{ "unsigned long liovcnt", "%lu", 8 },	
		{ "const struct iovec *rvec", "%p", 8 },	
		{ "unsigned long riovcnt", "%lu", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 311, "process_vm_writev", 6, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "const struct iovec *lvec", "%p", 8 },	
		{ "unsigned long liovcnt", "%lu", 8 },	
		{ "const struct iovec *rvec", "%p", 8 },	
		{ "unsigned long riovcnt", "%lu", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 312, "kcmp", 5, { 
		{ "pid_t pid1", "%lu", 8 },	
		{ "pid_t pid2", "%lu", 8 },	
		{ "int type", "%i", 4 },	
		{ "unsigned long idx1", "%lu", 8 },	
		{ "unsigned long idx2", "%lu", 8 },	
		} },
		{ 313, "finit_module", 3, { 
		{ "int fd", "%i", 4 },	
		{ "const char *uargs", "%s", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 314, "sched_setattr", 3, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "struct sched_attr *attr", "%p", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 315, "sched_getattr", 4, { 
		{ "pid_t pid", "%lu", 8 },	
		{ "struct sched_attr *attr", "%p", 8 },	
		{ "unsigned int size", "%i", 4 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 316, "renameat2", 5, { 
		{ "int olddfd", "%i", 4 },	
		{ "const char *oldname", "%s", 8 },	
		{ "int newdfd", "%i", 4 },	
		{ "const char *newname", "%s", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 317, "seccomp", 3, { 
		{ "unsigned int op", "%i", 4 },	
		{ "unsigned int flags", "%i", 4 },	
		{ "void *uargs", "%p", 8 },	
		} },
		{ 318, "getrandom", 3, { 
		{ "char *buf", "%s", 8 },	
		{ "size_t count", "%lu", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 319, "memfd_create", 2, { 
		{ "const char *uname_ptr", "%s", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 320, "kexec_file_load", 5, { 
		{ "int kernel_fd", "%i", 4 },	
		{ "int initrd_fd", "%i", 4 },	
		{ "unsigned long cmdline_len", "%lu", 8 },	
		{ "const char *cmdline_ptr", "%s", 8 },	
		{ "unsigned long flags", "%lu", 8 },	
		} },
		{ 321, "bpf", 3, { 
		{ "int cmd", "%i", 4 },	
		{ "union bpf_attr *attr", "%p", 8 },	
		{ "unsigned int size", "%i", 4 },	
		} },
		{ 322, "execveat", 5, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *filename", "%s", 8 },	
		{ "const char *const *argv", "%p", 8 },	
		{ "const char *const *envp", "%p", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 323, "userfaultfd", 1, { 
		{ "int flags", "%i", 4 },	
		} },
		{ 324, "membarrier", 2, { 
		{ "int cmd", "%i", 4 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 325, "mlock2", 3, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "int flags", "%i", 4 },	
		} },
		{ 326, "copy_file_range", 6, { 
		{ "int fd_in", "%i", 4 },	
		{ "loff_t *off_in", "%p", 8 },	
		{ "int fd_out", "%i", 4 },	
		{ "loff_t *off_out", "%p", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "unsigned int flags", "%i", 4 },	
		} },
		{ 327, "preadv2", 6, { 
		{ "unsigned long fd", "%lu", 8 },	
		{ "const struct iovec *vec", "%p", 8 },	
		{ "unsigned long vlen", "%lu", 8 },	
		{ "unsigned long pos_l", "%lu", 8 },	
		{ "unsigned long pos_h", "%lu", 8 },	
		{ "rwf_t flags", "%lu", 8 },	
		} },
		{ 328, "pwritev2", 6, { 
		{ "unsigned long fd", "%lu", 8 },	
		{ "const struct iovec *vec", "%p", 8 },	
		{ "unsigned long vlen", "%lu", 8 },	
		{ "unsigned long pos_l", "%lu", 8 },	
		{ "unsigned long pos_h", "%lu", 8 },	
		{ "rwf_t flags", "%lu", 8 },	
		} },
		{ 329, "pkey_mprotect", 4, { 
		{ "unsigned long start", "%lu", 8 },	
		{ "size_t len", "%lu", 8 },	
		{ "unsigned long prot", "%lu", 8 },	
		{ "int pkey", "%i", 4 },	
		} },
		{ 330, "pkey_alloc", 2, { 
		{ "unsigned long flags", "%lu", 8 },	
		{ "unsigned long init_val", "%lu", 8 },	
		} },
		{ 331, "pkey_free", 1, { 
		{ "int pkey", "%i", 4 },	
		} },
		{ 332, "statx", 5, { 
		{ "int dfd", "%i", 4 },	
		{ "const char *path", "%s", 8 },	
		{ "unsigned flags", "%lu", 8 },	
		{ "unsigned mask", "%lu", 8 },	
		{ "struct statx *buffer", "%p", 8 },	
		} },
	};

	return &syscalls[nr];
}

