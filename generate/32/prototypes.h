/**   0 */ long restart_syscall();
/**   1 */ long exit(int error_code);
/**   2 */ long fork();
/**   3 */ long read(unsigned int fd, char *buf, size_t count);
/**   4 */ long write(unsigned int fd, const char *buf, size_t count);
/**   5 */ long open(const char *filename, int flags, umode_t mode);
/**   6 */ long close(unsigned int fd);
/**   7 */ long waitpid(pid_t pid, int *stat_addr, int options);
/**   8 */ long creat(const char *pathname, umode_t mode);
/**   9 */ long link(const char *oldname, const char *newname);
/**  10 */ long unlink(const char *pathname);
/**  11 */ long execve(const char *filename, const char *const *argv, const char *const *envp);
/**  12 */ long chdir(const char *filename);
/**  13 */ long time(__kernel_old_time_t *tloc);
/**  14 */ long mknod(const char *filename, umode_t mode, unsigned dev);
/**  15 */ long chmod(const char *filename, umode_t mode);
/**  16 */ long lchown(const char *filename, uid_t user, gid_t group);
/**  17 */ long break(); // Missing definition
/**  18 */ long oldstat(); // Missing definition
/**  19 */ long lseek(unsigned int fd, off_t offset, unsigned int whence);
/**  20 */ long getpid();
/**  21 */ long mount(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data);
/**  22 */ long umount(char *name, int flags);
/**  23 */ long setuid(uid_t uid);
/**  24 */ long getuid();
/**  25 */ long stime(__kernel_old_time_t *tptr);
/**  26 */ long ptrace(long request, long pid, unsigned long addr, unsigned long data);
/**  27 */ long alarm(unsigned int seconds);
/**  28 */ long oldfstat(); // Missing definition
/**  29 */ long pause();
/**  30 */ long utime(char *filename, struct utimbuf *times);
/**  31 */ long stty(); // Missing definition
/**  32 */ long gtty(); // Missing definition
/**  33 */ long access(const char *filename, int mode);
/**  34 */ long nice(int increment);
/**  35 */ long ftime(); // Missing definition
/**  36 */ long sync();
/**  37 */ long kill(pid_t pid, int sig);
/**  38 */ long rename(const char *oldname, const char *newname);
/**  39 */ long mkdir(const char *pathname, umode_t mode);
/**  40 */ long rmdir(const char *pathname);
/**  41 */ long dup(unsigned int fildes);
/**  42 */ long pipe(int *fildes);
/**  43 */ long times(struct tms *tbuf);
/**  44 */ long prof(); // Missing definition
/**  45 */ void *brk(unsigned long brk);
/**  46 */ long setgid(gid_t gid);
/**  47 */ long getgid();
/**  48 */ long signal(int sig, __sighandler_t handler);
/**  49 */ long geteuid();
/**  50 */ long getegid();
/**  51 */ long acct(const char *name);
/**  52 */ long umount2(); // Missing definition
/**  53 */ long lock(); // Missing definition
/**  54 */ long ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
/**  55 */ long fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
/**  56 */ long mpx(); // Missing definition
/**  57 */ long setpgid(pid_t pid, pid_t pgid);
/**  58 */ long ulimit(); // Missing definition
/**  59 */ long oldolduname(); // Missing definition
/**  60 */ long umask(int mask);
/**  61 */ long chroot(const char *filename);
/**  62 */ long ustat(unsigned dev, struct ustat *ubuf);
/**  63 */ long dup2(unsigned int oldfd, unsigned int newfd);
/**  64 */ long getppid();
/**  65 */ long getpgrp();
/**  66 */ long setsid();
/**  67 */ long sigaction(int sig, const struct old_sigaction *act, struct old_sigaction *oact);
/**  68 */ long sgetmask();
/**  69 */ long ssetmask(int newmask);
/**  70 */ long setreuid(uid_t ruid, uid_t euid);
/**  71 */ long setregid(gid_t rgid, gid_t egid);
/**  72 */ long sigsuspend(old_sigset_t mask);
/**  73 */ long sigpending(old_sigset_t *uset);
/**  74 */ long sethostname(char *name, int len);
/**  75 */ long setrlimit(unsigned int resource, struct rlimit *rlim);
/**  76 */ long getrlimit(unsigned int resource, struct rlimit *rlim);
/**  77 */ long getrusage(int who, struct rusage *ru);
/**  78 */ long gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz);
/**  79 */ long settimeofday(struct __kernel_old_timeval *tv, struct timezone *tz);
/**  80 */ long getgroups(int gidsetsize, gid_t *grouplist);
/**  81 */ long setgroups(int gidsetsize, gid_t *grouplist);
/**  82 */ long select(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct __kernel_old_timeval *tvp);
/**  83 */ long symlink(const char *oldname, const char *newname);
/**  84 */ long oldlstat(); // Missing definition
/**  85 */ long readlink(const char *path, char *buf, int bufsiz);
/**  86 */ long uselib(const char *library);
/**  87 */ long swapon(const char *specialfile, int swap_flags);
/**  88 */ long reboot(int magic1, int magic2, unsigned int cmd, void *arg);
/**  89 */ long readdir(); // Missing definition
/**  90 */ void *mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);
/**  91 */ long munmap(unsigned long addr, size_t len);
/**  92 */ long truncate(const char *path, long length);
/**  93 */ long ftruncate(unsigned int fd, off_t length);
/**  94 */ long fchmod(unsigned int fd, umode_t mode);
/**  95 */ long fchown(unsigned int fd, uid_t user, gid_t group);
/**  96 */ long getpriority(int which, int who);
/**  97 */ long setpriority(int which, int who, int niceval);
/**  98 */ long profil(); // Missing definition
/**  99 */ long statfs(const char *pathname, struct statfs *buf);
/** 100 */ long fstatfs(unsigned int fd, struct statfs *buf);
/** 101 */ long ioperm(unsigned long from, unsigned long num, int turn_on);
/** 102 */ long socketcall(int call, unsigned long *args);
/** 103 */ long syslog(int type, char *buf, int len);
/** 104 */ long setitimer(int which, struct __kernel_old_itimerval *value, struct __kernel_old_itimerval *ovalue);
/** 105 */ long getitimer(int which, struct __kernel_old_itimerval *value);
/** 106 */ long stat(const char *filename, struct __old_kernel_stat *statbuf);
/** 107 */ long lstat(const char *filename, struct __old_kernel_stat *statbuf);
/** 108 */ long fstat(unsigned int fd, struct __old_kernel_stat *statbuf);
/** 109 */ long olduname(struct oldold_utsname *name);
/** 110 */ long iopl(unsigned int level);
/** 111 */ long vhangup();
/** 112 */ long idle(); // Missing definition
/** 113 */ long vm86old(struct vm86_struct *user_vm86);
/** 114 */ long wait4(pid_t upid, int *stat_addr, int options, struct rusage *ru);
/** 115 */ long swapoff(const char *specialfile);
/** 116 */ long sysinfo(struct sysinfo *info);
/** 117 */ long ipc(unsigned int call, int first, unsigned long second, unsigned long third, void *ptr, long fifth);
/** 118 */ long fsync(unsigned int fd);
/** 119 */ long sigreturn(); // Missing definition
/** 120 */ long clone(unsigned long clone_flags, unsigned long newsp);
/** 121 */ long setdomainname(char *name, int len);
/** 122 */ long uname(struct old_utsname *name);
/** 123 */ long modify_ldt(int  func , void * ptr , unsigned long  bytecount);
/** 124 */ long adjtimex(struct __kernel_timex *txc_p);
/** 125 */ long mprotect(unsigned long start, size_t len, unsigned long prot);
/** 126 */ long sigprocmask(int how, old_sigset_t *nset, old_sigset_t *oset);
/** 127 */ long create_module(); // Missing definition
/** 128 */ long init_module(void *umod, unsigned long len, const char *uargs);
/** 129 */ long delete_module(const char *name_user, unsigned int flags);
/** 130 */ long get_kernel_syms(); // Missing definition
/** 131 */ long quotactl(unsigned int cmd, const char *special, qid_t id, void *addr);
/** 132 */ long getpgid(pid_t pid);
/** 133 */ long fchdir(unsigned int fd);
/** 134 */ long bdflush(); // Missing definition
/** 135 */ long sysfs(int option, unsigned long arg1, unsigned long arg2);
/** 136 */ long personality(unsigned int personality);
/** 137 */ long afs_syscall(); // Missing definition
/** 138 */ long setfsuid(uid_t uid);
/** 139 */ long setfsgid(gid_t gid);
/** 140 */ long _llseek(); // Missing definition
/** 141 */ long getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
/** 142 */ long _newselect(); // Missing definition
/** 143 */ long flock(unsigned int fd, unsigned int cmd);
/** 144 */ long msync(unsigned long start, size_t len, int flags);
/** 145 */ long readv(unsigned long fd, const struct iovec *vec, unsigned long vlen);
/** 146 */ long writev(unsigned long fd, const struct iovec *vec, unsigned long vlen);
/** 147 */ long getsid(pid_t pid);
/** 148 */ long fdatasync(unsigned int fd);
/** 149 */ long _sysctl(); // Missing definition
/** 150 */ long mlock(unsigned long start, size_t len);
/** 151 */ long munlock(unsigned long start, size_t len);
/** 152 */ long mlockall(int flags);
/** 153 */ long munlockall();
/** 154 */ long sched_setparam(pid_t pid, struct sched_param *param);
/** 155 */ long sched_getparam(pid_t pid, struct sched_param *param);
/** 156 */ long sched_setscheduler(pid_t pid, int policy, struct sched_param *param);
/** 157 */ long sched_getscheduler(pid_t pid);
/** 158 */ long sched_yield();
/** 159 */ long sched_get_priority_max(int policy);
/** 160 */ long sched_get_priority_min(int policy);
/** 161 */ long sched_rr_get_interval(pid_t pid, struct __kernel_timespec *interval);
/** 162 */ long nanosleep(struct __kernel_timespec *rqtp, struct __kernel_timespec *rmtp);
/** 163 */ void *mremap(unsigned long addr, unsigned long old_len);
/** 164 */ long setresuid(uid_t ruid, uid_t euid, uid_t suid);
/** 165 */ long getresuid(uid_t *ruidp, uid_t *euidp, uid_t *suidp);
/** 166 */ long vm86(unsigned long cmd, unsigned long arg);
/** 167 */ long query_module(); // Missing definition
/** 168 */ long poll(struct pollfd *ufds, unsigned int nfds, int timeout_msecs);
/** 169 */ long nfsservctl(); // Missing definition
/** 170 */ long setresgid(gid_t rgid, gid_t egid, gid_t sgid);
/** 171 */ long getresgid(gid_t *rgidp, gid_t *egidp, gid_t *sgidp);
/** 172 */ long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
/** 173 */ long rt_sigreturn();
/** 174 */ long rt_sigaction(int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize);
/** 175 */ long rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize);
/** 176 */ long rt_sigpending(sigset_t *uset, size_t sigsetsize);
/** 177 */ long rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const struct __kernel_timespec *uts, size_t sigsetsize);
/** 178 */ long rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo);
/** 179 */ long rt_sigsuspend(sigset_t *unewset, size_t sigsetsize);
/** 180 */ long pread64(unsigned int fd, char *buf, size_t count, loff_t pos);
/** 181 */ long pwrite64(unsigned int fd, const char *buf, size_t count, loff_t pos);
/** 182 */ long chown(const char *filename, uid_t user, gid_t group);
/** 183 */ long getcwd(char *buf, unsigned long size);
/** 184 */ long capget(cap_user_header_t header, cap_user_data_t dataptr);
/** 185 */ long capset(cap_user_header_t header, const cap_user_data_t data);
/** 186 */ long sigaltstack(const stack_t *uss, stack_t *uoss);
/** 187 */ long sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
/** 188 */ long getpmsg(); // Missing definition
/** 189 */ long putpmsg(); // Missing definition
/** 190 */ long vfork();
/** 191 */ long ugetrlimit(); // Missing definition
/** 192 */ long mmap2(); // Missing definition
/** 193 */ long truncate64(const char *path, loff_t length);
/** 194 */ long ftruncate64(unsigned int fd, loff_t length);
/** 195 */ long stat64(const char *filename, struct stat64 *statbuf);
/** 196 */ long lstat64(const char *filename, struct stat64 *statbuf);
/** 197 */ long fstat64(unsigned long fd, struct stat64 *statbuf);
/** 198 */ long lchown32(); // Missing definition
/** 199 */ long getuid32(); // Missing definition
/** 200 */ long getgid32(); // Missing definition
/** 201 */ long geteuid32(); // Missing definition
/** 202 */ long getegid32(); // Missing definition
/** 203 */ long setreuid32(); // Missing definition
/** 204 */ long setregid32(); // Missing definition
/** 205 */ long getgroups32(); // Missing definition
/** 206 */ long setgroups32(); // Missing definition
/** 207 */ long fchown32(); // Missing definition
/** 208 */ long setresuid32(); // Missing definition
/** 209 */ long getresuid32(); // Missing definition
/** 210 */ long setresgid32(); // Missing definition
/** 211 */ long getresgid32(); // Missing definition
/** 212 */ long chown32(); // Missing definition
/** 213 */ long setuid32(); // Missing definition
/** 214 */ long setgid32(); // Missing definition
/** 215 */ long setfsuid32(); // Missing definition
/** 216 */ long setfsgid32(); // Missing definition
/** 217 */ long pivot_root(const char *new_root, const char *put_old);
/** 218 */ long mincore(unsigned long start, size_t len, unsigned char *vec);
/** 219 */ long madvise(unsigned long start, size_t len_in, int behavior);
/** 220 */ long getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
/** 221 */ long fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg);
/** 224 */ long gettid();
/** 225 */ long readahead(int fd, loff_t offset, size_t count);
/** 226 */ long setxattr(const char *pathname, const char *name, const void *value, size_t size, int flags);
/** 227 */ long lsetxattr(const char *pathname, const char *name, const void *value, size_t size, int flags);
/** 228 */ long fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);
/** 229 */ long getxattr(const char *pathname, const char *name, void *value, size_t size);
/** 230 */ long lgetxattr(const char *pathname, const char *name, void *value, size_t size);
/** 231 */ long fgetxattr(int fd, const char *name, void *value, size_t size);
/** 232 */ long listxattr(const char *pathname, char *list, size_t size);
/** 233 */ long llistxattr(const char *pathname, char *list, size_t size);
/** 234 */ long flistxattr(int fd, char *list, size_t size);
/** 235 */ long removexattr(const char *pathname, const char *name);
/** 236 */ long lremovexattr(const char *pathname, const char *name);
/** 237 */ long fremovexattr(int fd, const char *name);
/** 238 */ long tkill(pid_t pid, int sig);
/** 239 */ long sendfile64(int out_fd, int in_fd, loff_t *offset, size_t count);
/** 240 */ long futex(u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u32 val3);
/** 241 */ long sched_setaffinity(pid_t pid, unsigned int len, unsigned long *user_mask_ptr);
/** 242 */ long sched_getaffinity(pid_t pid, unsigned int len, unsigned long *user_mask_ptr);
/** 243 */ long set_thread_area(struct user_desc *u_info);
/** 244 */ long get_thread_area(struct user_desc *u_info);
/** 245 */ long io_setup(unsigned nr_events, aio_context_t *ctxp);
/** 246 */ long io_destroy(aio_context_t ctx);
/** 247 */ long io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout);
/** 248 */ long io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
/** 249 */ long io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
/** 250 */ long fadvise64(int fd, loff_t offset, size_t len, int advice);
/** 252 */ long exit_group(int error_code);
/** 253 */ long lookup_dcookie(); // Missing definition
/** 254 */ long epoll_create(int size);
/** 255 */ long epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
/** 256 */ long epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
/** 257 */ long remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
/** 258 */ long set_tid_address(int *tidptr);
/** 259 */ long timer_create(const clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id);
/** 260 */ long timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec *new_setting, struct __kernel_itimerspec *old_setting);
/** 261 */ long timer_gettime(timer_t timer_id, struct __kernel_itimerspec *setting);
/** 262 */ long timer_getoverrun(timer_t timer_id);
/** 263 */ long timer_delete(timer_t timer_id);
/** 264 */ long clock_settime(const clockid_t which_clock);
/** 265 */ long clock_gettime(const clockid_t which_clock);
/** 266 */ long clock_getres(const clockid_t which_clock, struct __kernel_timespec *tp);
/** 267 */ long clock_nanosleep(const clockid_t which_clock, int flags);
/** 268 */ long statfs64(const char *pathname, size_t sz, struct statfs64 *buf);
/** 269 */ long fstatfs64(unsigned int fd, size_t sz, struct statfs64 *buf);
/** 270 */ long tgkill(pid_t tgid, pid_t pid, int sig);
/** 271 */ long utimes(char *filename, struct __kernel_old_timeval *utimes);
/** 272 */ long fadvise64_64(int fd, loff_t offset, loff_t len, int advice);
/** 273 */ long vserver(); // Missing definition
/** 274 */ long mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long *nmask, unsigned long maxnode, unsigned int flags);
/** 275 */ long get_mempolicy(int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
/** 276 */ long set_mempolicy(int mode, const unsigned long *nmask, unsigned long maxnode);
/** 277 */ long mq_open(const char *u_name, int oflag, umode_t mode, struct mq_attr *u_attr);
/** 278 */ long mq_unlink(const char *u_name);
/** 279 */ long mq_timedsend(mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec *u_abs_timeout);
/** 280 */ long mq_timedreceive(mqd_t mqdes, char *u_msg_ptr, size_t msg_len, unsigned int *u_msg_prio, const struct __kernel_timespec *u_abs_timeout);
/** 281 */ long mq_notify(mqd_t mqdes, const struct sigevent *u_notification);
/** 282 */ long mq_getsetattr(mqd_t mqdes, const struct mq_attr *u_mqstat, struct mq_attr *u_omqstat);
/** 283 */ long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);
/** 284 */ long waitid(int which, pid_t upid, struct siginfo *infop, int options, struct rusage *ru);
/** 286 */ long add_key(const char *_type, const char *_description, const void *_payload, size_t plen, key_serial_t ringid);
/** 287 */ long request_key(const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid);
/** 288 */ long keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
/** 289 */ long ioprio_set(int which, int who, int ioprio);
/** 290 */ long ioprio_get(int which, int who);
/** 291 */ long inotify_init();
/** 292 */ long inotify_add_watch(int fd, const char *pathname, u32 mask);
/** 293 */ long inotify_rm_watch(int fd, __s32 wd);
/** 294 */ long migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);
/** 295 */ long openat(int dfd, const char *filename, int flags, umode_t mode);
/** 296 */ long mkdirat(int dfd, const char *pathname, umode_t mode);
/** 297 */ long mknodat(int dfd, const char *filename, umode_t mode, unsigned int dev);
/** 298 */ long fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag);
/** 299 */ long futimesat(int dfd, const char *filename, struct __kernel_old_timeval *utimes);
/** 300 */ long fstatat64(int dfd, const char *filename, struct stat64 *statbuf, int flag);
/** 301 */ long unlinkat(int dfd, const char *pathname, int flag);
/** 302 */ long renameat(int olddfd, const char *oldname, int newdfd, const char *newname);
/** 303 */ long linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
/** 304 */ long symlinkat(const char *oldname, int newdfd, const char *newname);
/** 305 */ long readlinkat(int dfd, const char *pathname, char *buf, int bufsiz);
/** 306 */ long fchmodat(int dfd, const char *filename, umode_t mode);
/** 307 */ long faccessat(int dfd, const char *filename, int mode);
/** 308 */ long pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct __kernel_timespec *tsp, void *sig);
/** 309 */ long ppoll(struct pollfd *ufds, unsigned int nfds, struct __kernel_timespec *tsp, const sigset_t *sigmask, size_t sigsetsize);
/** 310 */ long unshare(unsigned long unshare_flags);
/** 311 */ long set_robust_list(struct robust_list_head *head, size_t len);
/** 312 */ long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr);
/** 313 */ long splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
/** 314 */ long sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);
/** 315 */ long tee(int fdin, int fdout, size_t len, unsigned int flags);
/** 316 */ long vmsplice(int fd, const struct iovec *uiov, unsigned long nr_segs, unsigned int flags);
/** 317 */ long move_pages(pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags);
/** 318 */ long getcpu(unsigned *cpup, unsigned *nodep, struct getcpu_cache *unused);
/** 319 */ long epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask, size_t sigsetsize);
/** 320 */ long utimensat(int dfd, const char *filename, struct __kernel_timespec *utimes, int flags);
/** 321 */ long signalfd(int ufd, sigset_t *user_mask, size_t sizemask);
/** 322 */ long timerfd_create(int clockid, int flags);
/** 323 */ long eventfd(unsigned int count);
/** 324 */ long fallocate(int fd, int mode, loff_t offset, loff_t len);
/** 325 */ long timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec *utmr, struct __kernel_itimerspec *otmr);
/** 326 */ long timerfd_gettime(int ufd, struct __kernel_itimerspec *otmr);
/** 327 */ long signalfd4(int ufd, sigset_t *user_mask, size_t sizemask, int flags);
/** 328 */ long eventfd2(unsigned int count, int flags);
/** 329 */ long epoll_create1(int flags);
/** 330 */ long dup3(unsigned int oldfd, unsigned int newfd, int flags);
/** 331 */ long pipe2(int *fildes, int flags);
/** 332 */ long inotify_init1(int flags);
/** 333 */ long preadv(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
/** 334 */ long pwritev(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
/** 335 */ long rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo);
/** 336 */ long perf_event_open(struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
/** 337 */ long recvmmsg(int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags, struct __kernel_timespec *timeout);
/** 338 */ long fanotify_init(unsigned int flags, unsigned int event_f_flags);
/** 339 */ long fanotify_mark(int fanotify_fd, unsigned int flags, __u64 mask, int dfd, const char *pathname);
/** 340 */ long prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);
/** 341 */ long name_to_handle_at(int dfd, const char *name, struct file_handle *handle, void *mnt_id, int flag);
/** 342 */ long open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags);
/** 343 */ long clock_adjtime(const clockid_t which_clock, struct __kernel_timex *utx);
/** 344 */ long syncfs(int fd);
/** 345 */ long sendmmsg(int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags);
/** 346 */ long setns(int fd, int flags);
/** 347 */ long process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
/** 348 */ long process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);
/** 349 */ long kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
/** 350 */ long finit_module(int fd, const char *uargs, int flags);
/** 351 */ long sched_setattr(pid_t pid, struct sched_attr *uattr, unsigned int flags);
/** 352 */ long sched_getattr(pid_t pid, struct sched_attr *uattr, unsigned int usize, unsigned int flags);
/** 353 */ long renameat2(int olddfd, const char *oldname, int newdfd, const char *newname, unsigned int flags);
/** 354 */ long seccomp(unsigned int op, unsigned int flags, void *uargs);
/** 355 */ long getrandom(char *ubuf, size_t len, unsigned int flags);
/** 356 */ long memfd_create(const char *uname, unsigned int flags);
/** 357 */ long bpf(int cmd, union bpf_attr *uattr, unsigned int size);
/** 358 */ long execveat(int fd, const char *filename, const char *const *argv, const char *const *envp, int flags);
/** 359 */ long socket(int family, int type, int protocol);
/** 360 */ long socketpair(int family, int type, int protocol, int *usockvec);
/** 361 */ long bind(int fd, struct sockaddr *umyaddr, int addrlen);
/** 362 */ long connect(int fd, struct sockaddr *uservaddr, int addrlen);
/** 363 */ long listen(int fd, int backlog);
/** 364 */ long accept4(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags);
/** 365 */ long getsockopt(int fd, int level, int optname, char *optval, int *optlen);
/** 366 */ long setsockopt(int fd, int level, int optname, char *optval, int optlen);
/** 367 */ long getsockname(int fd, struct sockaddr *usockaddr, int *usockaddr_len);
/** 368 */ long getpeername(int fd, struct sockaddr *usockaddr, int *usockaddr_len);
/** 369 */ long sendto(int fd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
/** 370 */ long sendmsg(int fd, struct user_msghdr *msg, unsigned int flags);
/** 371 */ long recvfrom(int fd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len);
/** 372 */ long recvmsg(int fd, struct user_msghdr *msg, unsigned int flags);
/** 373 */ long shutdown(int fd, int how);
/** 374 */ long userfaultfd(int flags);
/** 375 */ long membarrier(int cmd, unsigned int flags, int cpu_id);
/** 376 */ long mlock2(unsigned long start, size_t len, int flags);
/** 377 */ long copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
/** 378 */ long preadv2(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
/** 379 */ long pwritev2(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
/** 380 */ long pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);
/** 381 */ long pkey_alloc(unsigned long flags, unsigned long init_val);
/** 382 */ long pkey_free(int pkey);
/** 383 */ long statx(int dfd, const char *filename, unsigned flags, unsigned int mask, struct statx *buffer);
/** 384 */ long arch_prctl(int option, unsigned long arg2);
/** 385 */ long io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct __kernel_timespec *timeout, const struct __aio_sigset *usig);
/** 386 */ long rseq(struct rseq *rseq, u32 rseq_len, int flags, u32 sig);
/** 393 */ long semget(key_t key, int nsems, int semflg);
/** 394 */ long semctl(int semid, int semnum, int cmd, unsigned long arg);
/** 395 */ long shmget(key_t key, size_t size, int shmflg);
/** 396 */ long shmctl(int shmid, int cmd, struct shmid_ds *buf);
/** 397 */ void *shmat(int shmid, char *shmaddr, int shmflg);
/** 398 */ long shmdt(char *shmaddr);
/** 399 */ long msgget(key_t key, int msgflg);
/** 400 */ long msgsnd(int msqid, struct msgbuf *msgp, size_t msgsz, int msgflg);
/** 401 */ long msgrcv(int msqid, struct msgbuf *msgp, size_t msgsz, long msgtyp, int msgflg);
/** 402 */ long msgctl(int msqid, int cmd, struct msqid_ds *buf);
/** 403 */ long clock_gettime64(); // Missing definition
/** 404 */ long clock_settime64(); // Missing definition
/** 405 */ long clock_adjtime64(); // Missing definition
/** 406 */ long clock_getres_time64(); // Missing definition
/** 407 */ long clock_nanosleep_time64(); // Missing definition
/** 408 */ long timer_gettime64(); // Missing definition
/** 409 */ long timer_settime64(); // Missing definition
/** 410 */ long timerfd_gettime64(); // Missing definition
/** 411 */ long timerfd_settime64(); // Missing definition
/** 412 */ long utimensat_time64(); // Missing definition
/** 413 */ long pselect6_time64(); // Missing definition
/** 414 */ long ppoll_time64(); // Missing definition
/** 416 */ long io_pgetevents_time64(); // Missing definition
/** 417 */ long recvmmsg_time64(); // Missing definition
/** 418 */ long mq_timedsend_time64(); // Missing definition
/** 419 */ long mq_timedreceive_time64(); // Missing definition
/** 420 */ long semtimedop_time64(); // Missing definition
/** 421 */ long rt_sigtimedwait_time64(); // Missing definition
/** 422 */ long futex_time64(); // Missing definition
/** 423 */ long sched_rr_get_interval_time64(); // Missing definition
/** 424 */ long pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags);
/** 425 */ long io_uring_setup(u32 entries, struct io_uring_params *params);
/** 426 */ long io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void *argp, size_t argsz);
/** 427 */ long io_uring_register(unsigned int fd, unsigned int opcode, void *arg, unsigned int nr_args);
/** 428 */ long open_tree(int dfd, const char *filename, unsigned flags);
/** 429 */ long move_mount(int from_dfd, const char *from_pathname, int to_dfd, const char *to_pathname, unsigned int flags);
/** 430 */ long fsopen(const char *_fs_name, unsigned int flags);
/** 431 */ long fsconfig(int fd, unsigned int cmd, const char *_key, const void *_value, int aux);
/** 432 */ long fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags);
/** 433 */ long fspick(int dfd, const char *path, unsigned int flags);
/** 434 */ long pidfd_open(pid_t pid, unsigned int flags);
/** 435 */ long clone3(struct clone_args *uargs, size_t size);
/** 436 */ long close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);
/** 437 */ long openat2(int dfd, const char *filename, struct open_how *how, size_t usize);
/** 438 */ long pidfd_getfd(int pidfd, int fd, unsigned int flags);
/** 439 */ long faccessat2(int dfd, const char *filename, int mode, int flags);
/** 440 */ long process_madvise(int pidfd, const struct iovec *vec, size_t vlen, int behavior, unsigned int flags);
/** 441 */ long epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct __kernel_timespec *timeout, const sigset_t *sigmask, size_t sigsetsize);
/** 442 */ long mount_setattr(int dfd, const char *path, unsigned int flags, struct mount_attr *uattr, size_t usize);
/** 443 */ long quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void *addr);
/** 444 */ long landlock_create_ruleset(const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags);
/** 445 */ long landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type, const void *const rule_attr, const __u32 flags);
/** 446 */ long landlock_restrict_self(const int ruleset_fd, const __u32 flags);
/** 447 */ long memfd_secret(unsigned int flags);
/** 448 */ long process_mrelease(int pidfd, unsigned int flags);
/** 449 */ long futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec *timeout, clockid_t clockid);
/** 450 */ long set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
/** 451 */ long cachestat(unsigned int fd, struct cachestat_range *cstat_range, struct cachestat *cstat, unsigned int flags);
/** 452 */ long fchmodat2(int dfd, const char *filename, umode_t mode, unsigned int flags);
/** 453 */ long map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags);
/** 454 */ long futex_wake(void *uaddr, unsigned long mask, int nr, unsigned int flags);
/** 455 */ long futex_wait(void *uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec *timeout, clockid_t clockid);
/** 456 */ long futex_requeue(struct futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue);
/** 457 */ long statmount(const struct mnt_id_req *req, struct statmount *buf, size_t bufsize, unsigned int flags);
/** 458 */ long listmount(const struct mnt_id_req *req, u64 *mnt_ids, size_t nr_mnt_ids, unsigned int flags);
/** 459 */ long lsm_get_self_attr(unsigned int attr, struct lsm_ctx *ctx, u32 *size, u32 flags);
/** 460 */ long lsm_set_self_attr(unsigned int attr, struct lsm_ctx *ctx, u32 size, u32 flags);
/** 461 */ long lsm_list_modules(u64 *ids, u32 *size, u32 flags);
/** 462 */ long mseal(unsigned long start, size_t len, unsigned long flags);
/** 463 */ long setxattrat(); // Missing definition
/** 464 */ long getxattrat(); // Missing definition
/** 465 */ long listxattrat(); // Missing definition
/** 466 */ long removexattrat(); // Missing definition
