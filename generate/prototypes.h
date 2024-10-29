#include <asm/prctl.h>
#include <asm/unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <keyutils.h>
#include <linux/aio_abi.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/getcpu.h>
#include <linux/hw_breakpoint.h>
#include <linux/kcmp.h>
#include <linux/kexec.h>
#include <linux/keyctl.h>
#include <linux/membarrier.h>
#include <linux/module.h>
#include <linux/nfsd/syscall.h>
#include <linux/openat2.h>
#include <linux/perf_event.h>
#include <linux/reboot.h>
#include <linux/seccomp.h>
#include <linux/signal.h>
#include <linux/sysctl.h>
#include <linux/time.h>
#include <linux/unistd.h>
#include <linux/userfaultfd.h>
#include <mqueue.h>
#include <numaif.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/capability.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/io.h>
#include <sys/ipc.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <ustat.h>
#include <utime.h>
#include <xfs/xqm.h>

/**   0 */ ssize_t read(int fd, void *buf, size_t count);
/**   1 */ ssize_t write(int fd, const void *buf, size_t count);
/**   2 */ int open(const char *pathname, int flags, mode_t mode);
/**   3 */ int close(int fd);
/**   4 */ int stat(const char *pathname, struct stat *statbuf);
/**   5 */ int fstat(int fd, struct stat *statbuf);
/**   6 */ int lstat(const char *pathname, struct stat *statbuf);
/**   7 */ int poll(struct pollfd *fds, nfds_t nfds, int timeout);
/**   8 */ off_t lseek(int fd, off_t offset, int whence);
/**   9 */ void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
/**  10 */ int mprotect(void *addr, size_t len, int prot);
/**  11 */ int munmap(void *addr, size_t length);
/**  12 */ int brk(void *addr);
/**  13 */ int rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t);
/**  14 */ int rt_sigprocmask(int, const sigset_t *, sigset_t *, size_t);
/**  15 */ int rt_sigreturn(...);
/**  16 */ int ioctl(int fd, unsigned long request, ...);
/**  17 */ ssize_t pread64(unsigned int fd, char *buf, size_t count, loff_t pos);
/**  18 */ ssize_t pwrite64(unsigned int fd, const char *buf, size_t count, loff_t pos);
/**  19 */ ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
/**  20 */ ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
/**  21 */ int access(const char *pathname, int mode);
/**  22 */ int pipe(int pipefds[2]);
/**  23 */ int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
/**  24 */ int sched_yield(void);
/**  25 */ void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
/**  26 */ int msync(void *addr, size_t length, int flags);
/**  27 */ int mincore(void *addr, size_t length, unsigned char *vec);
/**  28 */ int madvise(void *addr, size_t length, int advice);
/**  29 */ int shmget(key_t key, size_t size, int shmflg);
/**  30 */ void *shmat(int shmid, const void *shmaddr, int shmflg);
/**  31 */ int shmctl(int shmid, int cmd, struct shmid_ds *buf);
/**  32 */ int dup(int oldfd);
/**  33 */ int dup2(int oldfd, int newfd);
/**  34 */ int pause(void);
/**  35 */ int nanosleep(const struct timespec *req, struct timespec *rem);
/**  36 */ int getitimer(int which, struct itimerval *curr_value);
/**  37 */ unsigned int alarm(unsigned int seconds);
/**  38 */ int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
/**  39 */ pid_t getpid(void);
/**  40 */ ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
/**  41 */ int socket(int domain, int type, int protocol);
/**  42 */ int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
/**  43 */ int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
/**  44 */ ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
/**  45 */ ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
/**  46 */ ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
/**  47 */ ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
/**  48 */ int shutdown(int sockfd, int how);
/**  49 */ int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
/**  50 */ int listen(int sockfd, int backlog);
/**  51 */ int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
/**  52 */ int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
/**  53 */ int socketpair(int domain, int type, int protocol, int sv[2]);
/**  54 */ int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
/**  55 */ int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
/**  56 */ int clone(int (*fn)(void *), void *stack, int flags, void *arg, ... /* pid_t *parent_tid, void *tls, pid_t *child_tid */ );
/**  57 */ pid_t fork(void);
/**  58 */ pid_t vfork(void);
/**  59 */ int execve(const char *pathname, char *const argv[], char *const envp[]);
/**  60 */ void exit(int status);
/**  61 */ pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);
/**  62 */ int kill(pid_t pid, int sig);
/**  63 */ int uname(struct utsname *buf);
/**  64 */ int semget(key_t key, int nsems, int semflg);
/**  65 */ int semop(int semid, struct sembuf *sops, size_t nsops);
/**  66 */ int semctl(int semid, int semnum, int cmd, ...);
/**  67 */ int shmdt(const void *shmaddr);
/**  68 */ int msgget(key_t key, int msgflg);
/**  69 */ int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
/**  70 */ ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
/**  71 */ int msgctl(int msqid, int cmd, struct msqid_ds *buf);
/**  72 */ int fcntl(int fd, int cmd, ... /* arg */ );
/**  73 */ int flock(int fd, int operation);
/**  74 */ int fsync(int fd);
/**  75 */ int fdatasync(int fd);
/**  76 */ int truncate(const char *path, off_t length);
/**  77 */ int ftruncate(int fd, off_t length);
/**  78 */ long getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
/**  79 */ char *getcwd(char *buf, size_t size);
/**  80 */ int chdir(const char *path);
/**  81 */ int fchdir(int fd);
/**  82 */ int rename(const char *oldpath, const char *newpath);
/**  83 */ int mkdir(const char *pathname, mode_t mode);
/**  84 */ int rmdir(const char *pathname);
/**  85 */ int creat(const char *pathname, mode_t mode);
/**  86 */ int link(const char *oldpath, const char *newpath);
/**  87 */ int unlink(const char *pathname);
/**  88 */ int symlink(const char *target, const char *linkpath);
/**  89 */ ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
/**  90 */ int chmod(const char *pathname, mode_t mode);
/**  91 */ int fchmod(int fd, mode_t mode);
/**  92 */ int chown(const char *pathname, uid_t owner, gid_t group);
/**  93 */ int fchown(int fd, uid_t owner, gid_t group);
/**  94 */ int lchown(const char *pathname, uid_t owner, gid_t group);
/**  95 */ mode_t umask(mode_t mask);
/**  96 */ int gettimeofday(struct timeval *tv, struct timezone *tz);
/**  97 */ int getrlimit(int resource, struct rlimit *rlim);
/**  98 */ int getrusage(int who, struct rusage *usage);
/**  99 */ int sysinfo(struct sysinfo *info);
/** 100 */ clock_t times(struct tms *buf);
/** 101 */ long ptrace(enum _ptrace_request request, pid_t pid, void *addr, void *data);
/** 102 */ uid_t getuid(void);
/** 103 */ int syslog(int type, char *bufp, int len);
/** 104 */ gid_t getgid(void);
/** 105 */ int setuid(uid_t uid);
/** 106 */ int setgid(gid_t gid);
/** 107 */ uid_t geteuid(void);
/** 108 */ gid_t getegid(void);
/** 109 */ int setpgid(pid_t pid, pid_t pgid);
/** 110 */ pid_t getppid(void);
/** 111 */ /* POSIX.1 version */ pid_t getpgrp(pid_t pid);
/** 112 */ pid_t setsid(void);
/** 113 */ int setreuid(uid_t ruid, uid_t euid);
/** 114 */ int setregid(gid_t rgid, gid_t egid);
/** 115 */ int getgroups(int size, gid_t list[]);
/** 116 */ int setgroups(size_t size, const gid_t *list);
/** 117 */ int setresuid(uid_t ruid, uid_t euid, uid_t suid);
/** 118 */ int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
/** 119 */ int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
/** 120 */ int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
/** 121 */ pid_t getpgid(pid_t pid);
/** 122 */ int setfsuid(uid_t fsuid);
/** 123 */ int setfsgid(uid_t fsgid);
/** 124 */ pid_t getsid(pid_t pid);
/** 125 */ int capget(cap_user_header_t hdrp, cap_user_data_t datap);
/** 126 */ int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
/** 127 */ int rt_sigpending(sigset_t *set, size_t sigsetsize);
/** 128 */ int rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const struct _kernel_timespec *uts, size_t sigsetsize);
/** 129 */ int rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo);
/** 130 */ int rt_sigsuspend(sigset_t *unewset, size_t sigsetsize);
/** 131 */ int sigaltstack(const stack_t *ss, stack_t *old_ss);
/** 132 */ int utime(const char *filename, const struct utimbuf *times);
/** 133 */ int mknod(const char *pathname, mode_t mode, dev_t dev);
/** 134 */ int uselib(const char *library);
/** 135 */ int personality(unsigned long persona);
/** 136 */ int ustat(dev_t dev, struct ustat *ubuf);
/** 137 */ int statfs(const char *path, struct statfs *buf);
/** 138 */ int fstatfs(int fd, struct statfs *buf);
/** 139 */ int sysfs(int option, unsigned int fs_index, char *buf);
/** 140 */ int getpriority(int which, id_t who);
/** 141 */ int setpriority(int which, id_t who, int prio);
/** 142 */ int sched_setparam(pid_t pid, const struct sched_param *param);
/** 143 */ int sched_getparam(pid_t pid, struct sched_param *param);
/** 144 */ int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
/** 145 */ int sched_getscheduler(pid_t pid);
/** 146 */ int sched_get_priority_max(int policy);
/** 147 */ int sched_get_priority_min(int policy);
/** 148 */ int sched_rr_get_interval(pid_t pid, struct timespec *tp);
/** 149 */ int mlock(const void *addr, size_t len);
/** 150 */ int munlock(const void *addr, size_t len);
/** 151 */ int mlockall(int flags);
/** 152 */ int munlockall(void);
/** 153 */ int vhangup(void);
/** 154 */ int modify_ldt(int func, void *ptr, unsigned long bytecount);
/** 155 */ int pivot_root(const char *new_root, const char *put_old);
/** 156 */ int _sysctl(struct _sysctl_args *args);
/** 157 */ int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
/** 158 */ int arch_prctl(int code, unsigned long *addr);
/** 159 */ int adjtimex(struct timex *buf);
/** 160 */ int setrlimit(int resource, const struct rlimit *rlim);
/** 161 */ int chroot(const char *path);
/** 162 */ void sync(void);
/** 163 */ int acct(const char *filename);
/** 164 */ int settimeofday(const struct timeval *tv, const struct timezone *tz);
/** 165 */ int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
/** 166 */ int umount2(const char *target, int flags);
/** 167 */ int swapon(const char *path, int swapflags);
/** 168 */ int swapoff(const char *path);
/** 169 */ int reboot(int magic, int magic2, int cmd, void *arg);
/** 170 */ int sethostname(const char *name, size_t len);
/** 171 */ int setdomainname(const char *name, size_t len);
/** 172 */ int iopl(int level);
/** 173 */ int ioperm(unsigned long from, unsigned long num, int turn_on);
/** 174 */ caddr_t create_module(const char *name, size_t size);
/** 175 */ int init_module(void *module_image, unsigned long len, const char *param_values);
/** 176 */ int delete_module(const char *name, int flags);
/** 177 */ int get_kernel_syms(struct kernel_sym *table);
/** 178 */ int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret);
/** 179 */ int quotactl(int cmd, const char *special, int id, caddr_t addr);
/** 180 */ long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);
/** 181 */ int getpmsg(); /* Unimplemented */
/** 182 */ int putpmsg(); /* Unimplemented */
/** 183 */ int afs_syscall(); /* Unimplemented */
/** 184 */ int tuxcall(); /* Unimplemented */
/** 185 */ int security(); /* Unimplemented */
/** 186 */ pid_t gettid(void);
/** 187 */ ssize_t readahead(int fd, off64_t offset, size_t count);
/** 188 */ int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
/** 189 */ int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags);
/** 190 */ int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);
/** 191 */ ssize_t getxattr(const char *path, const char *name, void *value, size_t size);
/** 192 */ ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size);
/** 193 */ ssize_t fgetxattr(int fd, const char *name, void *value, size_t size);
/** 194 */ ssize_t listxattr(const char *path, char *list, size_t size);
/** 195 */ ssize_t llistxattr(const char *path, char *list, size_t size);
/** 196 */ ssize_t flistxattr(int fd, char *list, size_t size);
/** 197 */ int removexattr(const char *path, const char *name);
/** 198 */ int lremovexattr(const char *path, const char *name);
/** 199 */ int fremovexattr(int fd, const char *name);
/** 200 */ int tkill(int tid, int sig);
/** 201 */ time_t time(time_t *tloc);
/** 202 */ long futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, /* or: uint32_t val2 */ uint32_t *uaddr2, uint32_t val3);
/** 203 */ int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
/** 204 */ int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
/** 205 */ int set_thread_area(struct user_desc *u_info);
/** 206 */ long io_setup(unsigned nr_events, aio_context_t *ctx_idp);
/** 207 */ int io_destroy(aio_context_t ctx_id);
/** 208 */ int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout);
/** 209 */ int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
/** 210 */ int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
/** 211 */ int get_thread_area(struct user_desc *u_info);
/** 212 */ int lookup_dcookie(u64 cookie, char *buffer, size_t len);
/** 213 */ int epoll_create(int size);
/** 214 */ int epoll_ctl_old(int, int, struct e_poll_event *);
/** 215 */ int epoll_wait_old(int, struct e_poll_event *, int);
/** 216 */ int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags);
/** 217 */ ssize_t getdents64(int fd, void *dirp, size_t count);
/** 218 */ pid_t set_tid_address(int *tidptr);
/** 219 */ long restart_syscall(void);
/** 220 */ int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout);
/** 221 */ int fadvise64(int fd, loff_t offset, size_t len, int advice);
/** 222 */ int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
/** 223 */ int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
/** 224 */ int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
/** 225 */ int timer_getoverrun(timer_t timerid);
/** 226 */ int timer_delete(timer_t timerid);
/** 227 */ int clock_settime(clockid_t clockid, const struct timespec *tp);
/** 228 */ int clock_gettime(clockid_t clockid, struct timespec *tp);
/** 229 */ int clock_getres(clockid_t clockid, struct timespec *res);
/** 230 */ int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain);
/** 231 */ void exit_group(int status);
/** 232 */ int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
/** 233 */ int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
/** 234 */ int tgkill(int tgid, int tid, int sig);
/** 235 */ int utimes(const char *filename, const struct timeval times[2]);
/** 236 */ int vserver(); /* Unimplemented */
/** 237 */ long mbind(void *addr, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode, unsigned flags);
/** 238 */ long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
/** 239 */ long get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags);
/** 240 */ mqd_t mq_open(const char *name, int oflag, mode_t mode, struct mq_attr *attr);
/** 241 */ int mq_unlink(const char *name);
/** 242 */ int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout);
/** 243 */ ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout);
/** 244 */ int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
/** 245 */ int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);
/** 246 */ long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
/** 247 */ int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
/** 248 */ key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring);
/** 249 */ key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t dest_keyring);
/** 250 */ long keyctl(int operation, ...);
/** 251 */ int ioprio_set(int which, int who, int ioprio);
/** 252 */ int ioprio_get(int which, int who);
/** 253 */ int inotify_init(void);
/** 254 */ int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
/** 255 */ int inotify_rm_watch(int fd, int wd);
/** 256 */ long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
/** 257 */ int openat(int dirfd, const char *pathname, int flags, mode_t mode);
/** 258 */ int mkdirat(int dirfd, const char *pathname, mode_t mode);
/** 259 */ int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
/** 260 */ int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
/** 261 */ int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
/** 262 */ int newfstatat(int dfd, const char *filename, struct stat *statbuf, int flag);
/** 263 */ int unlinkat(int dirfd, const char *pathname, int flags);
/** 264 */ int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
/** 265 */ int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
/** 266 */ int symlinkat(const char *target, int newdirfd, const char *linkpath);
/** 267 */ ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
/** 268 */ int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
/** 269 */ int faccessat(int dirfd, const char *pathname, int mode, int flags);
/** 270 */ int pselect6(int, fd_set *, fd_set *, fd_set *, struct __kernel_timespec *, void *);
/** 271 */ int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
/** 272 */ int unshare(int flags);
/** 273 */ long set_robust_list(struct robust_list_head *head, size_t len);
/** 274 */ long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
/** 275 */ ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
/** 276 */ ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
/** 277 */ int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags);
/** 278 */ ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags);
/** 279 */ long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags);
/** 280 */ int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
/** 281 */ int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
/** 282 */ int signalfd(int fd, const sigset_t *mask, int flags);
/** 283 */ int timerfd_create(int clockid, int flags);
/** 284 */ int eventfd(unsigned int initval, int flags);
/** 285 */ int fallocate(int fd, int mode, off_t offset, off_t len);
/** 286 */ int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
/** 287 */ int timerfd_gettime(int fd, struct itimerspec *curr_value);
/** 288 */ int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
/** 289 */ int signalfd4(int ufd, sigset_t *user_mask, size_t sizemask, int flags);
/** 290 */ int eventfd2(unsigned int count, int flags);
/** 291 */ int epoll_create1(int flags);
/** 292 */ int dup3(int oldfd, int newfd, int flags);
/** 293 */ int pipe2(int pipefd[2], int flags);
/** 294 */ int inotify_init1(int flags);
/** 295 */ ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
/** 296 */ ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
/** 297 */ int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
/** 298 */ int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);
/** 299 */ int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
/** 300 */ int fanotify_init(unsigned int flags, unsigned int event_f_flags);
/** 301 */ int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname);
/** 302 */ int prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);
/** 303 */ int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags);
/** 304 */ int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
/** 305 */ int clock_adjtime(clockid_t clk_id, struct timex *buf);
/** 306 */ int syncfs(int fd);
/** 307 */ int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
/** 308 */ int setns(int fd, int nstype);
/** 309 */ int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
/** 310 */ int process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
/** 311 */ int process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
/** 312 */ int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
/** 313 */ int finit_module(int fd, const char *param_values, int flags);
/** 314 */ int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags);
/** 315 */ int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags);
/** 316 */ int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
/** 317 */ int seccomp(unsigned int operation, unsigned int flags, void *args);
/** 318 */ ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
/** 319 */ int memfd_create(const char *name, unsigned int flags);
/** 320 */ long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags);
/** 321 */ int bpf(int cmd, union bpf_attr *attr, unsigned int size);
/** 322 */ int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
/** 323 */ int userfaultfd(int flags);
/** 324 */ int membarrier(int cmd, unsigned int flags, int cpu_id);
/** 325 */ int mlock2(const void *addr, size_t len, int flags);
/** 326 */ ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
/** 327 */ ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
/** 328 */ ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
/** 329 */ int pkey_mprotect(void *addr, size_t len, int prot, int pkey);
/** 330 */ int pkey_alloc(unsigned int flags, unsigned int access_rights);
/** 331 */ int pkey_free(int pkey);
/** 332 */ int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
/** 424 */ int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags);
/** 434 */ int pidfd_open(pid_t pid, unsigned int flags);
/** 435 */ long clone3(struct clone_args *cl_args, size_t size);
/** 437 */ long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
/** 438 */ int pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
/** 439 */ int faccessat2(int dirfd, const char *pathname, int mode, int flags);

