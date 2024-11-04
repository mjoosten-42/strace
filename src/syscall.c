#include "syscall.h"

const t_syscall_prototype *syscall_get_prototype(int nr) {
	static const t_syscall_prototype syscalls[] = {
		/* read(int, void *, int) */
		{ 0, 3, "read", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* write(int, const void *, int) */
		{ 1, 3, "write", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* open(const char *, int, mode_t) */
		{ 2, 3, "open", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 }, { "%u", 4 } } },
		/* close(int) */
		{ 3, 1, "close", { "%i", 4 }, { { "%i", 4 } } },
		/* stat(const char *, struct stat *) */
		{ 4, 2, "stat", { "%i", 4 }, { { "%s", 8 }, { "%p", 8 } } },
		/* fstat(int, struct stat *) */
		{ 5, 2, "fstat", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* lstat(const char *, struct stat *) */
		{ 6, 2, "lstat", { "%i", 4 }, { { "%s", 8 }, { "%p", 8 } } },
		/* poll(struct pollfd *, nfds_t, int) */
		{ 7, 3, "poll", { "%i", 4 }, { { "%p", 8 }, { "%lu", 8 }, { "%i", 4 } } },
		/* lseek(int, off_t, int) */
		{ 8, 3, "lseek", { "%li", 8 }, { { "%i", 4 }, { "%li", 8 }, { "%i", 4 } } },
		/* mmap(void *, int, int, int, int, off_t) */
		{ 9,
		  6,
		  "mmap",
		  { "%p", 8 },
		  { { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%li", 8 } } },
		/* mprotect(void *, int, int) */
		{ 10, 3, "mprotect", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* munmap(void *, int) */
		{ 11, 2, "munmap", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 } } },
		/* brk(void *) */
		{ 12, 1, "brk", { "%i", 4 }, { { "%p", 8 } } },
		/* rt_sigaction(int, const struct sigaction *, struct sigaction *, int)
		 */
		{ 13, 4, "rt_sigaction", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* rt_sigprocmask(int, const sigset_t *, sigset_t *, int) */
		{ 14, 4, "rt_sigprocmask", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* rt_sigreturn(...) */
		{ 15, 0, "rt_sigreturn", { "%i", 4 }, {} },
		/* ioctl(int, unsigned long, ...) */
		{ 16, 2, "ioctl", { "%i", 4 }, { { "%i", 4 }, { "%lu", 8 } } },
		/* pread64(unsigned int, char *, int, loff_t) */
		{ 17, 4, "pread64", { "%li", 8 }, { { "%u", 4 }, { "%s", 8 }, { "%i", 4 }, { "%li", 8 } } },
		/* pwrite64(unsigned int, const char *, int, loff_t) */
		{ 18, 4, "pwrite64", { "%li", 8 }, { { "%u", 4 }, { "%s", 8 }, { "%i", 4 }, { "%li", 8 } } },
		/* readv(int, const struct iovec *, int) */
		{ 19, 3, "readv", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* writev(int, const struct iovec *, int) */
		{ 20, 3, "writev", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* access(const char *, int) */
		{ 21, 2, "access", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 } } },
		/* pipe(int *) */
		{ 22, 1, "pipe", { "%i", 4 }, { { "%p", 8 } } },
		/* select(int, fd_set *, fd_set *, fd_set *, struct timeval *) */
		{ 23, 5, "select", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* sched_yield() */
		{ 24, 0, "sched_yield", { "%i", 4 }, {} },
		/* mremap(void *, int, int, int, ...) */
		{ 25, 4, "mremap", { "%p", 8 }, { { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* msync(void *, int, int) */
		{ 26, 3, "msync", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* mincore(void *, int, unsigned char *) */
		{ 27, 3, "mincore", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%p", 8 } } },
		/* madvise(void *, int, int) */
		{ 28, 3, "madvise", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* shmget(key_t, int, int) */
		{ 29, 3, "shmget", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* shmat(int, const void *, int) */
		{ 30, 3, "shmat", { "%p", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* shmctl(int, int, struct shmid_ds *) */
		{ 31, 3, "shmctl", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* dup(int) */
		{ 32, 1, "dup", { "%i", 4 }, { { "%i", 4 } } },
		/* dup2(int, int) */
		{ 33, 2, "dup2", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* pause() */
		{ 34, 0, "pause", { "%i", 4 }, {} },
		/* nanosleep(const struct timespec *, struct timespec *) */
		{ 35, 2, "nanosleep", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 } } },
		/* getitimer(int, struct itimerval *) */
		{ 36, 2, "getitimer", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* alarm(unsigned int) */
		{ 37, 1, "alarm", { "%u", 4 }, { { "%u", 4 } } },
		/* setitimer(int, const struct itimerval *, struct itimerval *) */
		{ 38, 3, "setitimer", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* getpid() */
		{ 39, 0, "getpid", { "%i", 4 }, {} },
		/* sendfile(int, int, off_t *, int) */
		{ 40, 4, "sendfile", { "%li", 8 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* socket(int, int, int) */
		{ 41, 3, "socket", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* connect(int, const struct sockaddr *, socklen_t) */
		{ 42, 3, "connect", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* accept(int, struct sockaddr *, socklen_t *) */
		{ 43, 3, "accept", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* sendto(int, const void *, int, int, const struct sockaddr *,
		   socklen_t) */
		{ 44,
		  6,
		  "sendto",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* recvfrom(int, void *, int, int, struct sockaddr *, socklen_t *) */
		{ 45,
		  6,
		  "recvfrom",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* sendmsg(int, const struct msghdr *, int) */
		{ 46, 3, "sendmsg", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* recvmsg(int, struct msghdr *, int) */
		{ 47, 3, "recvmsg", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* shutdown(int, int) */
		{ 48, 2, "shutdown", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* bind(int, const struct sockaddr *, socklen_t) */
		{ 49, 3, "bind", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* listen(int, int) */
		{ 50, 2, "listen", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* getsockname(int, struct sockaddr *, socklen_t *) */
		{ 51, 3, "getsockname", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* getpeername(int, struct sockaddr *, socklen_t *) */
		{ 52, 3, "getpeername", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* socketpair(int, int, int, int *) */
		{ 53, 4, "socketpair", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* setsockopt(int, int, int, const void *, socklen_t) */
		{ 54, 5, "setsockopt", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* getsockopt(int, int, int, void *, socklen_t *) */
		{ 55, 5, "getsockopt", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* clone(int (*)(void *), void *, int, void *, ...) */
		{ 56, 4, "clone", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 }, { "%i", 4 }, { "%p", 8 } } },
		/* fork() */
		{ 57, 0, "fork", { "%i", 4 }, {} },
		/* vfork() */
		{ 58, 0, "vfork", { "%i", 4 }, {} },
		/* execve(const char *, char *const *, char *const *) */
		{ 59, 3, "execve", { "%i", 4 }, { { "%s", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* exit(int) */
		{ 60, 1, "exit", { "%i", -2 }, { { "%i", 4 } } },
		/* wait4(pid_t, int *, int, struct rusage *) */
		{ 61, 4, "wait4", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%p", 8 } } },
		/* kill(pid_t, int) */
		{ 62, 2, "kill", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* uname(struct utsname *) */
		{ 63, 1, "uname", { "%i", 4 }, { { "%p", 8 } } },
		/* semget(key_t, int, int) */
		{ 64, 3, "semget", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* semop(int, struct sembuf *, int) */
		{ 65, 3, "semop", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* semctl(int, int, int, ...) */
		{ 66, 3, "semctl", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* shmdt(const void *) */
		{ 67, 1, "shmdt", { "%i", 4 }, { { "%p", 8 } } },
		/* msgget(key_t, int) */
		{ 68, 2, "msgget", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* msgsnd(int, const void *, int, int) */
		{ 69, 4, "msgsnd", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* msgrcv(int, void *, int, long, int) */
		{ 70, 5, "msgrcv", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%li", 8 }, { "%i", 4 } } },
		/* msgctl(int, int, struct msqid_ds *) */
		{ 71, 3, "msgctl", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* fcntl(int, int, ...) */
		{ 72, 2, "fcntl", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* flock(int, int) */
		{ 73, 2, "flock", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* fsync(int) */
		{ 74, 1, "fsync", { "%i", 4 }, { { "%i", 4 } } },
		/* fdatasync(int) */
		{ 75, 1, "fdatasync", { "%i", 4 }, { { "%i", 4 } } },
		/* truncate(const char *, off_t) */
		{ 76, 2, "truncate", { "%i", 4 }, { { "%s", 8 }, { "%li", 8 } } },
		/* ftruncate(int, off_t) */
		{ 77, 2, "ftruncate", { "%i", 4 }, { { "%i", 4 }, { "%li", 8 } } },
		/* getdents(unsigned int, struct linux_dirent *, unsigned int) */
		{ 78, 3, "getdents", { "%li", 8 }, { { "%u", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* getcwd(char *, int) */
		{ 79, 2, "getcwd", { "%s", 8 }, { { "%s", 8 }, { "%i", 4 } } },
		/* chdir(const char *) */
		{ 80, 1, "chdir", { "%i", 4 }, { { "%s", 8 } } },
		/* fchdir(int) */
		{ 81, 1, "fchdir", { "%i", 4 }, { { "%i", 4 } } },
		/* rename(const char *, const char *) */
		{ 82, 2, "rename", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 } } },
		/* mkdir(const char *, mode_t) */
		{ 83, 2, "mkdir", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 } } },
		/* rmdir(const char *) */
		{ 84, 1, "rmdir", { "%i", 4 }, { { "%s", 8 } } },
		/* creat(const char *, mode_t) */
		{ 85, 2, "creat", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 } } },
		/* link(const char *, const char *) */
		{ 86, 2, "link", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 } } },
		/* unlink(const char *) */
		{ 87, 1, "unlink", { "%i", 4 }, { { "%s", 8 } } },
		/* symlink(const char *, const char *) */
		{ 88, 2, "symlink", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 } } },
		/* readlink(const char *, char *, int) */
		{ 89, 3, "readlink", { "%li", 8 }, { { "%s", 8 }, { "%s", 8 }, { "%i", 4 } } },
		/* chmod(const char *, mode_t) */
		{ 90, 2, "chmod", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 } } },
		/* fchmod(int, mode_t) */
		{ 91, 2, "fchmod", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 } } },
		/* chown(const char *, uid_t, gid_t) */
		{ 92, 3, "chown", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 }, { "%u", 4 } } },
		/* fchown(int, uid_t, gid_t) */
		{ 93, 3, "fchown", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 }, { "%u", 4 } } },
		/* lchown(const char *, uid_t, gid_t) */
		{ 94, 3, "lchown", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 }, { "%u", 4 } } },
		/* umask(mode_t) */
		{ 95, 1, "umask", { "%u", 4 }, { { "%u", 4 } } },
		/* gettimeofday(struct timeval *, struct timezone *) */
		{ 96, 2, "gettimeofday", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 } } },
		/* getrlimit(int, struct rlimit *) */
		{ 97, 2, "getrlimit", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* getrusage(int, struct rusage *) */
		{ 98, 2, "getrusage", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* sysinfo(struct sysinfo *) */
		{ 99, 1, "sysinfo", { "%i", 4 }, { { "%p", 8 } } },
		/* times(struct tms *) */
		{ 100, 1, "times", { "%li", 8 }, { { "%p", 8 } } },
		/* ptrace(enum _ptrace_request, pid_t, void *, void *) */
		{ 101, 4, "ptrace", { "%li", 8 }, { { "%d", 8 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* getuid() */
		{ 102, 0, "getuid", { "%u", 4 }, {} },
		/* syslog(int, char *, int) */
		{ 103, 3, "syslog", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 } } },
		/* getgid() */
		{ 104, 0, "getgid", { "%u", 4 }, {} },
		/* setuid(uid_t) */
		{ 105, 1, "setuid", { "%i", 4 }, { { "%u", 4 } } },
		/* setgid(gid_t) */
		{ 106, 1, "setgid", { "%i", 4 }, { { "%u", 4 } } },
		/* geteuid() */
		{ 107, 0, "geteuid", { "%u", 4 }, {} },
		/* getegid() */
		{ 108, 0, "getegid", { "%u", 4 }, {} },
		/* setpgid(pid_t, pid_t) */
		{ 109, 2, "setpgid", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* getppid() */
		{ 110, 0, "getppid", { "%i", 4 }, {} },
		/* getpgrp(pid_t) */
		{ 111, 1, "getpgrp", { "%i", 4 }, { { "%i", 4 } } },
		/* setsid() */
		{ 112, 0, "setsid", { "%i", 4 }, {} },
		/* setreuid(uid_t, uid_t) */
		{ 113, 2, "setreuid", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 } } },
		/* setregid(gid_t, gid_t) */
		{ 114, 2, "setregid", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 } } },
		/* getgroups(int, gid_t *) */
		{ 115, 2, "getgroups", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* setgroups(int, const gid_t *) */
		{ 116, 2, "setgroups", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* setresuid(uid_t, uid_t, uid_t) */
		{ 117, 3, "setresuid", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 }, { "%u", 4 } } },
		/* getresuid(uid_t *, uid_t *, uid_t *) */
		{ 118, 3, "getresuid", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* setresgid(gid_t, gid_t, gid_t) */
		{ 119, 3, "setresgid", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 }, { "%u", 4 } } },
		/* getresgid(gid_t *, gid_t *, gid_t *) */
		{ 120, 3, "getresgid", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* getpgid(pid_t) */
		{ 121, 1, "getpgid", { "%i", 4 }, { { "%i", 4 } } },
		/* setfsuid(uid_t) */
		{ 122, 1, "setfsuid", { "%i", 4 }, { { "%u", 4 } } },
		/* setfsgid(uid_t) */
		{ 123, 1, "setfsgid", { "%i", 4 }, { { "%u", 4 } } },
		/* getsid(pid_t) */
		{ 124, 1, "getsid", { "%i", 4 }, { { "%i", 4 } } },
		/* capget(int, int) */
		{ 125, 2, "capget", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* capset(int, const int) */
		{ 126, 2, "capset", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* rt_sigpending(sigset_t *, int) */
		{ 127, 2, "rt_sigpending", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 } } },
		/* rt_sigtimedwait(const sigset_t *, siginfo_t *, const struct
		   _kernel_timespec *, int) */
		{ 128, 4, "rt_sigtimedwait", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* rt_sigqueueinfo(pid_t, int, siginfo_t *) */
		{ 129, 3, "rt_sigqueueinfo", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* rt_sigsuspend(sigset_t *, int) */
		{ 130, 2, "rt_sigsuspend", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 } } },
		/* sigaltstack(const stack_t *, stack_t *) */
		{ 131, 2, "sigaltstack", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 } } },
		/* utime(const char *, const struct utimbuf *) */
		{ 132, 2, "utime", { "%i", 4 }, { { "%s", 8 }, { "%p", 8 } } },
		/* mknod(const char *, mode_t, dev_t) */
		{ 133, 3, "mknod", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 }, { "%lu", 8 } } },
		/* uselib(const char *) */
		{ 134, 1, "uselib", { "%i", 4 }, { { "%s", 8 } } },
		/* personality(unsigned long) */
		{ 135, 1, "personality", { "%i", 4 }, { { "%lu", 8 } } },
		/* ustat(dev_t, struct ustat *) */
		{ 136, 2, "ustat", { "%i", 4 }, { { "%lu", 8 }, { "%p", 8 } } },
		/* statfs(const char *, struct statfs *) */
		{ 137, 2, "statfs", { "%i", 4 }, { { "%s", 8 }, { "%p", 8 } } },
		/* fstatfs(int, struct statfs *) */
		{ 138, 2, "fstatfs", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* sysfs(int, unsigned int, char *) */
		{ 139, 3, "sysfs", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 }, { "%s", 8 } } },
		/* getpriority(int, id_t) */
		{ 140, 2, "getpriority", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 } } },
		/* setpriority(int, id_t, int) */
		{ 141, 3, "setpriority", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 }, { "%i", 4 } } },
		/* sched_setparam(pid_t, const struct sched_param *) */
		{ 142, 2, "sched_setparam", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* sched_getparam(pid_t, struct sched_param *) */
		{ 143, 2, "sched_getparam", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* sched_setscheduler(pid_t, int, const struct sched_param *) */
		{ 144, 3, "sched_setscheduler", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* sched_getscheduler(pid_t) */
		{ 145, 1, "sched_getscheduler", { "%i", 4 }, { { "%i", 4 } } },
		/* sched_get_priority_max(int) */
		{ 146, 1, "sched_get_priority_max", { "%i", 4 }, { { "%i", 4 } } },
		/* sched_get_priority_min(int) */
		{ 147, 1, "sched_get_priority_min", { "%i", 4 }, { { "%i", 4 } } },
		/* sched_rr_get_interval(pid_t, struct timespec *) */
		{ 148, 2, "sched_rr_get_interval", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* mlock(const void *, int) */
		{ 149, 2, "mlock", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 } } },
		/* munlock(const void *, int) */
		{ 150, 2, "munlock", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 } } },
		/* mlockall(int) */
		{ 151, 1, "mlockall", { "%i", 4 }, { { "%i", 4 } } },
		/* munlockall() */
		{ 152, 0, "munlockall", { "%i", 4 }, {} },
		/* vhangup() */
		{ 153, 0, "vhangup", { "%i", 4 }, {} },
		/* modify_ldt(int, void *, unsigned long) */
		{ 154, 3, "modify_ldt", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%lu", 8 } } },
		/* pivot_root(const char *, const char *) */
		{ 155, 2, "pivot_root", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 } } },
		/* _sysctl(struct _sysctl_args *) */
		{ 156, 1, "_sysctl", { "%i", 4 }, { { "%p", 8 } } },
		/* prctl(int, unsigned long, unsigned long, unsigned long, unsigned
		   long) */
		{ 157, 5, "prctl", { "%i", 4 }, { { "%i", 4 }, { "%lu", 8 }, { "%lu", 8 }, { "%lu", 8 }, { "%lu", 8 } } },
		/* arch_prctl(int, unsigned long *) */
		{ 158, 2, "arch_prctl", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* adjtimex(struct timex *) */
		{ 159, 1, "adjtimex", { "%i", 4 }, { { "%p", 8 } } },
		/* setrlimit(int, const struct rlimit *) */
		{ 160, 2, "setrlimit", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* chroot(const char *) */
		{ 161, 1, "chroot", { "%i", 4 }, { { "%s", 8 } } },
		/* sync() */
		{ 162, 0, "sync", { "%i", -2 }, {} },
		/* acct(const char *) */
		{ 163, 1, "acct", { "%i", 4 }, { { "%s", 8 } } },
		/* settimeofday(const struct timeval *, const struct timezone *) */
		{ 164, 2, "settimeofday", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 } } },
		/* mount(const char *, const char *, const char *, unsigned long, const
		   void *) */
		{ 165, 5, "mount", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 }, { "%s", 8 }, { "%lu", 8 }, { "%p", 8 } } },
		/* umount2(const char *, int) */
		{ 166, 2, "umount2", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 } } },
		/* swapon(const char *, int) */
		{ 167, 2, "swapon", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 } } },
		/* swapoff(const char *) */
		{ 168, 1, "swapoff", { "%i", 4 }, { { "%s", 8 } } },
		/* reboot(int, int, int, void *) */
		{ 169, 4, "reboot", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* sethostname(const char *, int) */
		{ 170, 2, "sethostname", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 } } },
		/* setdomainname(const char *, int) */
		{ 171, 2, "setdomainname", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 } } },
		/* iopl(int) */
		{ 172, 1, "iopl", { "%i", 4 }, { { "%i", 4 } } },
		/* ioperm(unsigned long, unsigned long, int) */
		{ 173, 3, "ioperm", { "%i", 4 }, { { "%lu", 8 }, { "%lu", 8 }, { "%i", 4 } } },
		/* create_module(const char *, int) */
		{ 174, 2, "create_module", { "%s", 8 }, { { "%s", 8 }, { "%i", 4 } } },
		/* init_module(void *, unsigned long, const char *) */
		{ 175, 3, "init_module", { "%i", 4 }, { { "%p", 8 }, { "%lu", 8 }, { "%s", 8 } } },
		/* delete_module(const char *, int) */
		{ 176, 2, "delete_module", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 } } },
		/* get_kernel_syms(struct kernel_sym *) */
		{ 177, 1, "get_kernel_syms", { "%i", 4 }, { { "%p", 8 } } },
		/* query_module(const char *, int, void *, int, int *) */
		{ 178, 5, "query_module", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%p", 8 } } },
		/* quotactl(int, const char *, int, caddr_t) */
		{ 179, 4, "quotactl", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%s", 8 } } },
		/* nfsservctl(int, struct nfsctl_arg *, union nfsctl_res *) */
		{ 180, 3, "nfsservctl", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* getpmsg() */
		{ 181, 0, "getpmsg", { "%i", 4 }, {} },
		/* putpmsg() */
		{ 182, 0, "putpmsg", { "%i", 4 }, {} },
		/* afs_syscall() */
		{ 183, 0, "afs_syscall", { "%i", 4 }, {} },
		/* tuxcall() */
		{ 184, 0, "tuxcall", { "%i", 4 }, {} },
		/* security() */
		{ 185, 0, "security", { "%i", 4 }, {} },
		/* gettid() */
		{ 186, 0, "gettid", { "%i", 4 }, {} },
		/* readahead(int, int, int) */
		{ 187, 3, "readahead", { "%li", 8 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* setxattr(const char *, const char *, const void *, int, int) */
		{ 188, 5, "setxattr", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* lsetxattr(const char *, const char *, const void *, int, int) */
		{ 189, 5, "lsetxattr", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* fsetxattr(int, const char *, const void *, int, int) */
		{ 190, 5, "fsetxattr", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* getxattr(const char *, const char *, void *, int) */
		{ 191, 4, "getxattr", { "%li", 8 }, { { "%s", 8 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* lgetxattr(const char *, const char *, void *, int) */
		{ 192, 4, "lgetxattr", { "%li", 8 }, { { "%s", 8 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* fgetxattr(int, const char *, void *, int) */
		{ 193, 4, "fgetxattr", { "%li", 8 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* listxattr(const char *, char *, int) */
		{ 194, 3, "listxattr", { "%li", 8 }, { { "%s", 8 }, { "%s", 8 }, { "%i", 4 } } },
		/* llistxattr(const char *, char *, int) */
		{ 195, 3, "llistxattr", { "%li", 8 }, { { "%s", 8 }, { "%s", 8 }, { "%i", 4 } } },
		/* flistxattr(int, char *, int) */
		{ 196, 3, "flistxattr", { "%li", 8 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 } } },
		/* removexattr(const char *, const char *) */
		{ 197, 2, "removexattr", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 } } },
		/* lremovexattr(const char *, const char *) */
		{ 198, 2, "lremovexattr", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 } } },
		/* fremovexattr(int, const char *) */
		{ 199, 2, "fremovexattr", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 } } },
		/* tkill(int, int) */
		{ 200, 2, "tkill", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* time(time_t *) */
		{ 201, 1, "time", { "%li", 8 }, { { "%p", 8 } } },
		/* futex(uint32_t *, int, uint32_t, const struct timespec *, uint32_t *,
		   uint32_t) */
		{ 202,
		  6,
		  "futex",
		  { "%li", 8 },
		  { { "%p", 8 }, { "%i", 4 }, { "%u", 4 }, { "%p", 8 }, { "%p", 8 }, { "%u", 4 } } },
		/* sched_setaffinity(pid_t, int, const cpu_set_t *) */
		{ 203, 3, "sched_setaffinity", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* sched_getaffinity(pid_t, int, cpu_set_t *) */
		{ 204, 3, "sched_getaffinity", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* set_thread_area(struct user_desc *) */
		{ 205, 1, "set_thread_area", { "%i", 4 }, { { "%p", 8 } } },
		/* io_setup(unsigned int, aio_context_t *) */
		{ 206, 2, "io_setup", { "%li", 8 }, { { "%u", 4 }, { "%p", 8 } } },
		/* io_destroy(aio_context_t) */
		{ 207, 1, "io_destroy", { "%i", 4 }, { { "%lu", 8 } } },
		/* io_getevents(aio_context_t, long, long, struct io_event *, struct
		   timespec *) */
		{ 208, 5, "io_getevents", { "%i", 4 }, { { "%lu", 8 }, { "%li", 8 }, { "%li", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* io_submit(aio_context_t, long, struct iocb **) */
		{ 209, 3, "io_submit", { "%i", 4 }, { { "%lu", 8 }, { "%li", 8 }, { "%p", 8 } } },
		/* io_cancel(aio_context_t, struct iocb *, struct io_event *) */
		{ 210, 3, "io_cancel", { "%i", 4 }, { { "%lu", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* get_thread_area(struct user_desc *) */
		{ 211, 1, "get_thread_area", { "%i", 4 }, { { "%p", 8 } } },
		/* lookup_dcookie(int, char *, int) */
		{ 212, 3, "lookup_dcookie", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 } } },
		/* epoll_create(int) */
		{ 213, 1, "epoll_create", { "%i", 4 }, { { "%i", 4 } } },
		/* epoll_ctl_old(int, int, struct e_poll_event *) */
		{ 214, 3, "epoll_ctl_old", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* epoll_wait_old(int, struct e_poll_event *, int) */
		{ 215, 3, "epoll_wait_old", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* remap_file_pages(void *, int, int, int, int) */
		{ 216,
		  5,
		  "remap_file_pages",
		  { "%i", 4 },
		  { { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* getdents64(int, void *, int) */
		{ 217, 3, "getdents64", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* set_tid_address(int *) */
		{ 218, 1, "set_tid_address", { "%i", 4 }, { { "%p", 8 } } },
		/* restart_syscall() */
		{ 219, 0, "restart_syscall", { "%li", 8 }, {} },
		/* semtimedop(int, struct sembuf *, int, const struct timespec *) */
		{ 220, 4, "semtimedop", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%p", 8 } } },
		/* fadvise64(int, loff_t, int, int) */
		{ 221, 4, "fadvise64", { "%i", 4 }, { { "%i", 4 }, { "%li", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* timer_create(clockid_t, struct sigevent *, timer_t *) */
		{ 222, 3, "timer_create", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* timer_settime(timer_t, int, const struct itimerspec *, struct
		   itimerspec *) */
		{ 223, 4, "timer_settime", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* timer_gettime(timer_t, struct itimerspec *) */
		{ 224, 2, "timer_gettime", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 } } },
		/* timer_getoverrun(timer_t) */
		{ 225, 1, "timer_getoverrun", { "%i", 4 }, { { "%p", 8 } } },
		/* timer_delete(timer_t) */
		{ 226, 1, "timer_delete", { "%i", 4 }, { { "%p", 8 } } },
		/* clock_settime(clockid_t, const struct timespec *) */
		{ 227, 2, "clock_settime", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* clock_gettime(clockid_t, struct timespec *) */
		{ 228, 2, "clock_gettime", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* clock_getres(clockid_t, struct timespec *) */
		{ 229, 2, "clock_getres", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* clock_nanosleep(clockid_t, int, const struct timespec *, struct
		   timespec *) */
		{ 230, 4, "clock_nanosleep", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* exit_group(int) */
		{ 231, 1, "exit_group", { "%i", -2 }, { { "%i", 4 } } },
		/* epoll_wait(int, struct epoll_event *, int, int) */
		{ 232, 4, "epoll_wait", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* epoll_ctl(int, int, int, struct epoll_event *) */
		{ 233, 4, "epoll_ctl", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* tgkill(int, int, int) */
		{ 234, 3, "tgkill", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* utimes(const char *, const struct timeval *) */
		{ 235, 2, "utimes", { "%i", 4 }, { { "%s", 8 }, { "%p", 32 } } },
		/* vserver() */
		{ 236, 0, "vserver", { "%i", 4 }, {} },
		/* mbind(void *, unsigned long, int, const unsigned long *, unsigned
		   long, unsigned int) */
		{ 237,
		  6,
		  "mbind",
		  { "%li", 8 },
		  { { "%p", 8 }, { "%lu", 8 }, { "%i", 4 }, { "%p", 8 }, { "%lu", 8 }, { "%u", 4 } } },
		/* set_mempolicy(int, const unsigned long *, unsigned long) */
		{ 238, 3, "set_mempolicy", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%lu", 8 } } },
		/* get_mempolicy(int *, unsigned long *, unsigned long, void *, unsigned
		   long) */
		{ 239,
		  5,
		  "get_mempolicy",
		  { "%li", 8 },
		  { { "%p", 8 }, { "%p", 8 }, { "%lu", 8 }, { "%p", 8 }, { "%lu", 8 } } },
		/* mq_open(const char *, int, mode_t, struct mq_attr *) */
		{ 240, 4, "mq_open", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 }, { "%u", 4 }, { "%p", 8 } } },
		/* mq_unlink(const char *) */
		{ 241, 1, "mq_unlink", { "%i", 4 }, { { "%s", 8 } } },
		/* mq_timedsend(mqd_t, const char *, int, unsigned int, const struct
		   timespec *) */
		{ 242, 5, "mq_timedsend", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%u", 4 }, { "%p", 8 } } },
		/* mq_timedreceive(mqd_t, char *, int, unsigned int *, const struct
		   timespec *) */
		{ 243,
		  5,
		  "mq_timedreceive",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* mq_notify(mqd_t, const struct sigevent *) */
		{ 244, 2, "mq_notify", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* mq_getsetattr(mqd_t, const struct mq_attr *, struct mq_attr *) */
		{ 245, 3, "mq_getsetattr", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* kexec_load(unsigned long, unsigned long, struct kexec_segment *,
		   unsigned long) */
		{ 246, 4, "kexec_load", { "%li", 8 }, { { "%lu", 8 }, { "%lu", 8 }, { "%p", 8 }, { "%lu", 8 } } },
		/* waitid(idtype_t, id_t, siginfo_t *, int) */
		{ 247, 4, "waitid", { "%i", 4 }, { { "%d", 4 }, { "%u", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* add_key(const char *, const char *, const void *, int, int) */
		{ 248, 5, "add_key", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* request_key(const char *, const char *, const char *, int) */
		{ 249, 4, "request_key", { "%i", 4 }, { { "%s", 8 }, { "%s", 8 }, { "%s", 8 }, { "%i", 4 } } },
		/* keyctl(int, ...) */
		{ 250, 1, "keyctl", { "%li", 8 }, { { "%i", 4 } } },
		/* ioprio_set(int, int, int) */
		{ 251, 3, "ioprio_set", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* ioprio_get(int, int) */
		{ 252, 2, "ioprio_get", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* inotify_init() */
		{ 253, 0, "inotify_init", { "%i", 4 }, {} },
		/* inotify_add_watch(int, const char *, uint32_t) */
		{ 254, 3, "inotify_add_watch", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%u", 4 } } },
		/* inotify_rm_watch(int, int) */
		{ 255, 2, "inotify_rm_watch", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* migrate_pages(int, unsigned long, const unsigned long *, const
		   unsigned long *) */
		{ 256, 4, "migrate_pages", { "%li", 8 }, { { "%i", 4 }, { "%lu", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* openat(int, const char *, int, mode_t) */
		{ 257, 4, "openat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%u", 4 } } },
		/* mkdirat(int, const char *, mode_t) */
		{ 258, 3, "mkdirat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%u", 4 } } },
		/* mknodat(int, const char *, mode_t, dev_t) */
		{ 259, 4, "mknodat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%u", 4 }, { "%lu", 8 } } },
		/* fchownat(int, const char *, uid_t, gid_t, int) */
		{ 260, 5, "fchownat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%u", 4 }, { "%u", 4 }, { "%i", 4 } } },
		/* futimesat(int, const char *, const struct timeval *) */
		{ 261, 3, "futimesat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 32 } } },
		/* newfstatat(int, const char *, struct stat *, int) */
		{ 262, 4, "newfstatat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* unlinkat(int, const char *, int) */
		{ 263, 3, "unlinkat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 } } },
		/* renameat(int, const char *, int, const char *) */
		{ 264, 4, "renameat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%s", 8 } } },
		/* linkat(int, const char *, int, const char *, int) */
		{ 265, 5, "linkat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%s", 8 }, { "%i", 4 } } },
		/* symlinkat(const char *, int, const char *) */
		{ 266, 3, "symlinkat", { "%i", 4 }, { { "%s", 8 }, { "%i", 4 }, { "%s", 8 } } },
		/* readlinkat(int, const char *, char *, int) */
		{ 267, 4, "readlinkat", { "%li", 8 }, { { "%i", 4 }, { "%s", 8 }, { "%s", 8 }, { "%i", 4 } } },
		/* fchmodat(int, const char *, mode_t, int) */
		{ 268, 4, "fchmodat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%u", 4 }, { "%i", 4 } } },
		/* faccessat(int, const char *, int, int) */
		{ 269, 4, "faccessat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* pselect6(int, fd_set *, fd_set *, fd_set *, struct __kernel_timespec
		 *, void *) */
		{ 270,
		  6,
		  "pselect6",
		  { "%i", 4 },
		  { { "%i", 4 }, { "%p", 8 }, { "%p", 8 }, { "%p", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* ppoll(struct pollfd *, nfds_t, const struct timespec *, const
		   sigset_t *) */
		{ 271, 4, "ppoll", { "%i", 4 }, { { "%p", 8 }, { "%lu", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* unshare(int) */
		{ 272, 1, "unshare", { "%i", 4 }, { { "%i", 4 } } },
		/* set_robust_list(struct robust_list_head *, int) */
		{ 273, 2, "set_robust_list", { "%li", 8 }, { { "%p", 8 }, { "%i", 4 } } },
		/* get_robust_list(int, struct robust_list_head **, int *) */
		{ 274, 3, "get_robust_list", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* splice(int, loff_t *, int, loff_t *, int, unsigned int) */
		{ 275,
		  6,
		  "splice",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%u", 4 } } },
		/* tee(int, int, int, unsigned int) */
		{ 276, 4, "tee", { "%li", 8 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%u", 4 } } },
		/* sync_file_range(int, int, int, unsigned int) */
		{ 277, 4, "sync_file_range", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%u", 4 } } },
		/* vmsplice(int, const struct iovec *, unsigned long, unsigned int) */
		{ 278, 4, "vmsplice", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%lu", 8 }, { "%u", 4 } } },
		/* move_pages(int, unsigned long, void **, const int *, int *, int) */
		{ 279,
		  6,
		  "move_pages",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%lu", 8 }, { "%p", 8 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* utimensat(int, const char *, const struct timespec *, int) */
		{ 280, 4, "utimensat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 32 }, { "%i", 4 } } },
		/* epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *) */
		{ 281, 5, "epoll_pwait", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* signalfd(int, const sigset_t *, int) */
		{ 282, 3, "signalfd", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* timerfd_create(int, int) */
		{ 283, 2, "timerfd_create", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* eventfd(unsigned int, int) */
		{ 284, 2, "eventfd", { "%i", 4 }, { { "%u", 4 }, { "%i", 4 } } },
		/* fallocate(int, int, off_t, off_t) */
		{ 285, 4, "fallocate", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%li", 8 }, { "%li", 8 } } },
		/* timerfd_settime(int, int, const struct itimerspec *, struct
		   itimerspec *) */
		{ 286, 4, "timerfd_settime", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* timerfd_gettime(int, struct itimerspec *) */
		{ 287, 2, "timerfd_gettime", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* accept4(int, struct sockaddr *, socklen_t *, int) */
		{ 288, 4, "accept4", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* signalfd4(int, sigset_t *, int, int) */
		{ 289, 4, "signalfd4", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* eventfd2(unsigned int, int) */
		{ 290, 2, "eventfd2", { "%i", 4 }, { { "%u", 4 }, { "%i", 4 } } },
		/* epoll_create1(int) */
		{ 291, 1, "epoll_create1", { "%i", 4 }, { { "%i", 4 } } },
		/* dup3(int, int, int) */
		{ 292, 3, "dup3", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* pipe2(int *, int) */
		{ 293, 2, "pipe2", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 } } },
		/* inotify_init1(int) */
		{ 294, 1, "inotify_init1", { "%i", 4 }, { { "%i", 4 } } },
		/* preadv(int, const struct iovec *, int, off_t) */
		{ 295, 4, "preadv", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%li", 8 } } },
		/* pwritev(int, const struct iovec *, int, off_t) */
		{ 296, 4, "pwritev", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%li", 8 } } },
		/* rt_tgsigqueueinfo(pid_t, pid_t, int, siginfo_t *) */
		{ 297, 4, "rt_tgsigqueueinfo", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* perf_event_open(struct perf_event_attr *, pid_t, int, int, unsigned
		   long) */
		{ 298,
		  5,
		  "perf_event_open",
		  { "%i", 4 },
		  { { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%lu", 8 } } },
		/* recvmmsg(int, struct mmsghdr *, unsigned int, int, struct timespec *)
		 */
		{ 299, 5, "recvmmsg", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 }, { "%i", 4 }, { "%p", 8 } } },
		/* fanotify_init(unsigned int, unsigned int) */
		{ 300, 2, "fanotify_init", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 } } },
		/* fanotify_mark(int, unsigned int, uint64_t, int, const char *) */
		{ 301, 5, "fanotify_mark", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 }, { "%lu", 8 }, { "%i", 4 }, { "%s", 8 } } },
		/* prlimit64(pid_t, unsigned int, const struct rlimit64 *, struct
		   rlimit64 *) */
		{ 302, 4, "prlimit64", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 }, { "%p", 8 }, { "%p", 8 } } },
		/* name_to_handle_at(int, const char *, struct file_handle *, int *,
		   int) */
		{ 303,
		  5,
		  "name_to_handle_at",
		  { "%i", 4 },
		  { { "%i", 4 }, { "%s", 8 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* open_by_handle_at(int, struct file_handle *, int) */
		{ 304, 3, "open_by_handle_at", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 } } },
		/* clock_adjtime(clockid_t, struct timex *) */
		{ 305, 2, "clock_adjtime", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 } } },
		/* syncfs(int) */
		{ 306, 1, "syncfs", { "%i", 4 }, { { "%i", 4 } } },
		/* sendmmsg(int, struct mmsghdr *, unsigned int, int) */
		{ 307, 4, "sendmmsg", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 }, { "%i", 4 } } },
		/* setns(int, int) */
		{ 308, 2, "setns", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 } } },
		/* getcpu(unsigned int *, unsigned int *, struct getcpu_cache *) */
		{ 309, 3, "getcpu", { "%i", 4 }, { { "%p", 8 }, { "%p", 8 }, { "%p", 8 } } },
		/* process_vm_readv(pid_t, const struct iovec *, unsigned long, const
		   struct iovec *, unsigned long, unsigned long) */
		{ 310,
		  6,
		  "process_vm_readv",
		  { "%i", 4 },
		  { { "%i", 4 }, { "%p", 8 }, { "%lu", 8 }, { "%p", 8 }, { "%lu", 8 }, { "%lu", 8 } } },
		/* process_vm_writev(pid_t, const struct iovec *, unsigned long, const
		   struct iovec *, unsigned long, unsigned long) */
		{ 311,
		  6,
		  "process_vm_writev",
		  { "%i", 4 },
		  { { "%i", 4 }, { "%p", 8 }, { "%lu", 8 }, { "%p", 8 }, { "%lu", 8 }, { "%lu", 8 } } },
		/* kcmp(pid_t, pid_t, int, unsigned long, unsigned long) */
		{ 312, 5, "kcmp", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%i", 4 }, { "%lu", 8 }, { "%lu", 8 } } },
		/* finit_module(int, const char *, int) */
		{ 313, 3, "finit_module", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 } } },
		/* sched_setattr(pid_t, struct sched_attr *, unsigned int) */
		{ 314, 3, "sched_setattr", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int)
		 */
		{ 315, 4, "sched_getattr", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 }, { "%u", 4 } } },
		/* renameat2(int, const char *, int, const char *, unsigned int) */
		{ 316, 5, "renameat2", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%s", 8 }, { "%u", 4 } } },
		/* seccomp(unsigned int, unsigned int, void *) */
		{ 317, 3, "seccomp", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 }, { "%p", 8 } } },
		/* getrandom(void *, int, unsigned int) */
		{ 318, 3, "getrandom", { "%li", 8 }, { { "%p", 8 }, { "%i", 4 }, { "%u", 4 } } },
		/* memfd_create(const char *, unsigned int) */
		{ 319, 2, "memfd_create", { "%i", 4 }, { { "%s", 8 }, { "%u", 4 } } },
		/* kexec_file_load(int, int, unsigned long, const char *, unsigned long)
		 */
		{ 320,
		  5,
		  "kexec_file_load",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%i", 4 }, { "%lu", 8 }, { "%s", 8 }, { "%lu", 8 } } },
		/* bpf(int, union bpf_attr *, unsigned int) */
		{ 321, 3, "bpf", { "%i", 4 }, { { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		/* execveat(int, const char *, char *const *, char *const *, int) */
		{ 322, 5, "execveat", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* userfaultfd(int) */
		{ 323, 1, "userfaultfd", { "%i", 4 }, { { "%i", 4 } } },
		/* membarrier(int, unsigned int, int) */
		{ 324, 3, "membarrier", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 }, { "%i", 4 } } },
		/* mlock2(const void *, int, int) */
		{ 325, 3, "mlock2", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%i", 4 } } },
		/* copy_file_range(int, loff_t *, int, loff_t *, int, unsigned int) */
		{ 326,
		  6,
		  "copy_file_range",
		  { "%li", 8 },
		  { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%u", 4 } } },
		/* preadv2(int, const struct iovec *, int, off_t, int) */
		{ 327, 5, "preadv2", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%li", 8 }, { "%i", 4 } } },
		/* pwritev2(int, const struct iovec *, int, off_t, int) */
		{ 328, 5, "pwritev2", { "%li", 8 }, { { "%i", 4 }, { "%p", 8 }, { "%i", 4 }, { "%li", 8 }, { "%i", 4 } } },
		/* pkey_mprotect(void *, int, int, int) */
		{ 329, 4, "pkey_mprotect", { "%i", 4 }, { { "%p", 8 }, { "%i", 4 }, { "%i", 4 }, { "%i", 4 } } },
		/* pkey_alloc(unsigned int, unsigned int) */
		{ 330, 2, "pkey_alloc", { "%i", 4 }, { { "%u", 4 }, { "%u", 4 } } },
		/* pkey_free(int) */
		{ 331, 1, "pkey_free", { "%i", 4 }, { { "%i", 4 } } },
		/* statx(int, const char *, int, unsigned int, struct statx *) */
		{ 332, 5, "statx", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%u", 4 }, { "%p", 8 } } },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		/* pidfd_send_signal(int, int, siginfo_t *, unsigned int) */
		{ 424, 4, "pidfd_send_signal", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%p", 8 }, { "%u", 4 } } },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		{ 0 },
		/* pidfd_open(pid_t, unsigned int) */
		{ 434, 2, "pidfd_open", { "%i", 4 }, { { "%i", 4 }, { "%u", 4 } } },
		/* clone3(struct clone_args *, int) */
		{ 435, 2, "clone3", { "%li", 8 }, { { "%p", 8 }, { "%i", 4 } } },
		{ 0 },
		/* openat2(int, const char *, struct open_how *, int) */
		{ 437, 4, "openat2", { "%li", 8 }, { { "%i", 4 }, { "%s", 8 }, { "%p", 8 }, { "%i", 4 } } },
		/* pidfd_getfd(int, int, unsigned int) */
		{ 438, 3, "pidfd_getfd", { "%i", 4 }, { { "%i", 4 }, { "%i", 4 }, { "%u", 4 } } },
		/* faccessat2(int, const char *, int, int) */
		{ 439, 4, "faccessat2", { "%i", 4 }, { { "%i", 4 }, { "%s", 8 }, { "%i", 4 }, { "%i", 4 } } },
	};

	return &syscalls[nr];
}
