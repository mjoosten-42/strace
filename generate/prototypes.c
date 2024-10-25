
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
#include <sys/capability.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/io.h>
#include <sys/ioctl.h>
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
#include <syscall.h>
#include <time.h>
#include <unistd.h>
#include <ustat.h>
#include <utime.h>
#include <xfs/xqm.h>

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int open(const char *pathname, int flags, mode_t mode);
int close(int fd);
int stat(const char *pathname, struct stat *statbuf);
int fstat(int fd, struct stat *statbuf);
int lstat(const char *pathname, struct stat *statbuf);
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
off_t lseek(int fd, off_t offset, int whence);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int mprotect(void *addr, size_t len, int prot);
int munmap(void *addr, size_t length);
int brk(void *addr);
int rt_sigprocmask(int how, const kernel_sigset_t *set, kernel_sigset_t *oldset, size_t sigsetsize);
int ioctl(int fd, unsigned long request, ...);
ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
int access(const char *pathname, int mode);
struct fd_pair pipe();
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int sched_yield(void);
void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
int msync(void *addr, size_t length, int flags);
int mincore(void *addr, size_t length, unsigned char *vec);
int madvise(void *addr, size_t length, int advice);
int shmget(key_t key, size_t size, int shmflg);
void *shmat(int shmid, const void *shmaddr, int shmflg);
int shmctl(int shmid, int cmd, struct shmid_ds *buf);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int pause(void);
int nanosleep(const struct timespec *req, struct timespec *rem);
int getitimer(int which, struct itimerval *curr_value);
unsigned int alarm(unsigned int seconds);
int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value);
pid_t getpid(void);
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
int socket(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
int shutdown(int sockfd, int how);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int socketpair(int domain, int type, int protocol, int sv[2]);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ... /* pid_t *parent_tid, void *tls, pid_t *child_tid */ );
pid_t fork(void);
pid_t vfork(void);
int execve(const char *pathname, char *const argv[], char *const envp[]);
pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);
int kill(pid_t pid, int sig);
int uname(struct utsname *buf);
int semget(key_t key, int nsems, int semflg);
int semop(int semid, struct sembuf *sops, size_t nsops);
int semctl(int semid, int semnum, int cmd, ...);
int shmdt(const void *shmaddr);
int msgget(key_t key, int msgflg);
int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
int msgctl(int msqid, int cmd, struct msqid_ds *buf);
int fcntl(int fd, int cmd, ... /* arg */ );
int flock(int fd, int operation);
int fsync(int fd);
int fdatasync(int fd);
int truncate(const char *path, off_t length);
int ftruncate(int fd, off_t length);
long getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
char *getcwd(char *buf, size_t size);
int chdir(const char *path);
int fchdir(int fd);
int rename(const char *oldpath, const char *newpath);
int mkdir(const char *pathname, mode_t mode);
int rmdir(const char *pathname);
int creat(const char *pathname, mode_t mode);
int link(const char *oldpath, const char *newpath);
int unlink(const char *pathname);
int symlink(const char *target, const char *linkpath);
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
int chmod(const char *pathname, mode_t mode);
int fchmod(int fd, mode_t mode);
int chown(const char *pathname, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);
int lchown(const char *pathname, uid_t owner, gid_t group);
mode_t umask(mode_t mask);
int gettimeofday(struct timeval *tv, struct timezone *tz);
int getrlimit(int resource, struct rlimit *rlim);
int getrusage(int who, struct rusage *usage);
int sysinfo(struct sysinfo *info);
clock_t times(struct tms *buf);
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
uid_t getuid(void);
int syslog(int type, char *bufp, int len);
gid_t getgid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
uid_t geteuid(void);
gid_t getegid(void);
int setpgid(pid_t pid, pid_t pgid);
pid_t getppid(void);
/* POSIX.1 version */ pid_t getpgrp(pid_t pid);
pid_t setsid(void);
int setreuid(uid_t ruid, uid_t euid);
int setregid(gid_t rgid, gid_t egid);
int getgroups(int size, gid_t list[]);
int setgroups(size_t size, const gid_t *list);
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
pid_t getpgid(pid_t pid);
int setfsuid(uid_t fsuid);
int setfsgid(uid_t fsgid);
pid_t getsid(pid_t pid);
int capget(cap_user_header_t hdrp, cap_user_data_t datap);
int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info);
int sigaltstack(const stack_t *ss, stack_t *old_ss);
int utime(const char *filename, const struct utimbuf *times);
int mknod(const char *pathname, mode_t mode, dev_t dev);
int uselib(const char *library);
int personality(unsigned long persona);
int ustat(dev_t dev, struct ustat *ubuf);
int statfs(const char *path, struct statfs *buf);
int fstatfs(int fd, struct statfs *buf);
int sysfs(int option, const char *fsname);
int getpriority(int which, id_t who);
int setpriority(int which, id_t who, int prio);
int sched_setparam(pid_t pid, const struct sched_param *param);
int sched_getparam(pid_t pid, struct sched_param *param);
int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
int sched_getscheduler(pid_t pid);
int sched_get_priority_max(int policy);
int sched_get_priority_min(int policy);
int sched_rr_get_interval(pid_t pid, struct timespec *tp);
int mlock(const void *addr, size_t len);
int munlock(const void *addr, size_t len);
int mlockall(int flags);
int munlockall(void);
int vhangup(void);
int modify_ldt(int func, void *ptr, unsigned long bytecount);
int pivot_root(const char *new_root, const char *put_old);
int _sysctl(struct __sysctl_args *args);
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
int arch_prctl(int code, unsigned long *addr);
int adjtimex(struct timex *buf);
int setrlimit(int resource, const struct rlimit *rlim);
int chroot(const char *path);
void sync(void);
int acct(const char *filename);
int settimeofday(const struct timeval *tv, const struct timezone *tz);
int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags,
int umount2(const char *target, int flags);
int swapon(const char *path, int swapflags);
int swapoff(const char *path);
int reboot(int magic, int magic2, int cmd, void *arg);
int sethostname(const char *name, size_t len);
int setdomainname(const char *name, size_t len);
int iopl(int level);
int ioperm(unsigned long from, unsigned long num, int turn_on);
caddr_t create_module(const char *name, size_t size);
int init_module(void *module_image, unsigned long len, const char *param_values);
int delete_module(const char *name, int flags);
int get_kernel_syms(struct kernel_sym *table);
int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret);
int quotactl(int cmd, const char *special, int id, caddr_t addr);
long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp);
pid_t gettid(void);
ssize_t readahead(int fd, off64_t offset, size_t count);
int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags);
int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);
ssize_t getxattr(const char *path, const char *name, void *value, size_t size);
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size);
ssize_t fgetxattr(int fd, const char *name, void *value, size_t size);
ssize_t listxattr(const char *path, char *list, size_t size);
ssize_t llistxattr(const char *path, char *list, size_t size);
ssize_t flistxattr(int fd, char *list, size_t size);
int removexattr(const char *path, const char *name);
int lremovexattr(const char *path, const char *name);
int fremovexattr(int fd, const char *name);
int tkill(int tid, int sig);
time_t time(time_t *tloc);
long futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, /* or: uint32_t val2 */
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
int set_thread_area(struct user_desc *u_info);
long io_setup(unsigned nr_events, aio_context_t *ctx_idp);
int io_destroy(aio_context_t ctx_id);
int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout);
int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
int get_thread_area(struct user_desc *u_info);
int lookup_dcookie(u64 cookie, char *buffer, size_t len);
int epoll_create(int size);
int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags);
ssize_t getdents64(int fd, void *dirp, size_t count);
pid_t set_tid_address(int *tidptr);
long restart_syscall(void);
int semtimedop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout);
int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value,
int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
int timer_getoverrun(timer_t timerid);
int timer_delete(timer_t timerid);
int clock_settime(clockid_t clockid, const struct timespec *tp);
int clock_gettime(clockid_t clockid, struct timespec *tp);
int clock_getres(clockid_t clockid, struct timespec *res);
int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request,
void exit_group(int status);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int tgkill(int tgid, int tid, int sig);
int utimes(const char *filename, const struct timeval times[2]);
long mbind(void *addr, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode,
long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode);
long get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr,
mqd_t mq_open(const char *name, int oflag, mode_t mode,
int mq_unlink(const char *name);
int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio,
ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio,
int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr);
long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen,
key_serial_t request_key(const char *type, const char *description, const char *callout_info,
long keyctl(int operation, ...);
int ioprio_set(int which, int who, int ioprio);
int ioprio_get(int which, int who);
int inotify_init(void);
int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int inotify_rm_watch(int fd, int wd);
long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes,
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
int mkdirat(int dirfd, const char *pathname, mode_t mode);
int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
int futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
int unlinkat(int dirfd, const char *pathname, int flags);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
int symlinkat(const char *target, int newdirfd, const char *linkpath);
ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
int faccessat(int dirfd, const char *pathname, int mode, int flags);
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
int unshare(int flags);
long set_robust_list(struct robust_list_head *head, size_t len);
long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags);
ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags);
long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags);
int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
int signalfd(int fd, const sigset_t *mask, int flags);
int timerfd_create(int clockid, int flags);
int eventfd(unsigned int initval, int flags);
int fallocate(int fd, int mode, off_t offset, off_t len);
int timerfd_settime(int fd, int flags, const struct itimerspec *new_value,
int timerfd_gettime(int fd, struct itimerspec *curr_value);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int epoll_create1(int flags);
int dup3(int oldfd, int newfd, int flags);
int pipe2(int pipefd[2], int flags);
int inotify_init1(int flags);
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info);
int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd,
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
int fanotify_init(unsigned int flags, unsigned int event_f_flags);
int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname);
int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle,
int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
int clock_adjtime(clockid_t clk_id, struct timex *buf);
int syncfs(int fd);
int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
int setns(int fd, int nstype);
int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache);
ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov,
ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov,
int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
int finit_module(int fd, const char *param_values, int flags);
int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags);
int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags);
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
int seccomp(unsigned int operation, unsigned int flags, void *args);
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
int memfd_create(const char *name, unsigned int flags);
long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline,
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[],
int userfaultfd(int flags);
int membarrier(int cmd, unsigned int flags, int cpu_id);
int mlock2(const void *addr, size_t len, int flags);
ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
int pkey_mprotect(void *addr, size_t len, int prot, int pkey);
int pkey_alloc(unsigned int flags, unsigned int access_rights);
int pkey_free(int pkey);
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags);
int pidfd_open(pid_t pid, unsigned int flags);
long clone3(struct clone_args *cl_args, size_t size);
long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
int pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
int faccessat2(int dirfd, const char *pathname, int mode, int flags);

