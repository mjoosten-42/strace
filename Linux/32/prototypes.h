/**   0 */ long restart_syscall();
/**   1 */ long exit(int error_code);
/**   2 */ long fork();
/**   3 */ long read(unsigned int fd, char __user *buf, size_t count);
/**   4 */ long write(unsigned int fd, const char __user *buf, size_t count);
/**   5 */ long open(const char __user *filename, int flags, umode_t mode);
/**   6 */ long close(unsigned int fd);
/**   7 */ long waitpid(pid_t pid, int __user *stat_addr, int options);
/**   8 */ long creat(const char __user *pathname, umode_t mode);
/**   9 */ long link(const char __user *oldname, const char __user *newname);
/**  10 */ long unlink(const char __user *pathname);
/**  11 */ long execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
/**  12 */ long chdir(const char __user *filename);
/**  13 */ long time(__kernel_old_time_t __user *tloc);
/**  14 */ long mknod(const char __user *filename, umode_t mode, unsigned dev);
/**  15 */ long chmod(const char __user *filename, umode_t mode);
/**  16 */ long lchown(const char __user *filename, uid_t user, gid_t group);
/**  17 */ long break(); // Missing definition
/**  18 */ long oldstat(); // Missing definition
/**  19 */ long lseek(unsigned int fd, off_t offset, unsigned int whence);
/**  20 */ long getpid();
/**  21 */ long mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);
/**  22 */ long umount(char __user *name, int flags);
/**  23 */ long setuid(uid_t uid);
/**  24 */ long getuid();
/**  25 */ long stime(__kernel_old_time_t __user *tptr);
/**  26 */ long ptrace(long request, long pid, unsigned long addr, unsigned long data);
/**  27 */ long alarm(unsigned int seconds);
/**  28 */ long oldfstat(); // Missing definition
/**  29 */ long pause();
/**  30 */ long utime(char __user *filename, struct utimbuf __user *times);
/**  31 */ long stty(); // Missing definition
/**  32 */ long gtty(); // Missing definition
/**  33 */ long access(const char __user *filename, int mode);
/**  34 */ long nice(int increment);
/**  35 */ long ftime(); // Missing definition
/**  36 */ long sync();
/**  37 */ long kill(pid_t pid, int sig);
/**  38 */ long rename(const char __user *oldname, const char __user *newname);
/**  39 */ long mkdir(const char __user *pathname, umode_t mode);
/**  40 */ long rmdir(const char __user *pathname);
/**  41 */ long dup(unsigned int fildes);
/**  42 */ long pipe(int __user *fildes);
/**  43 */ long times(struct tms __user *tbuf);
/**  44 */ long prof(); // Missing definition
/**  45 */ long brk(unsigned long brk);
/**  46 */ long setgid(gid_t gid);
/**  47 */ long getgid();
/**  48 */ long signal(int sig, __sighandler_t handler);
/**  49 */ long geteuid();
/**  50 */ long getegid();
/**  51 */ long acct(const char __user *name);
/**  52 */ long umount2(); // Missing definition
/**  53 */ long lock(); // Missing definition
/**  54 */ long ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
/**  55 */ long fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
/**  56 */ long mpx(); // Missing definition
/**  57 */ long setpgid(pid_t pid, pid_t pgid);
/**  58 */ long ulimit(); // Missing definition
/**  59 */ long oldolduname(); // Missing definition
/**  60 */ long umask(int mask);
/**  61 */ long chroot(const char __user *filename);
/**  62 */ long ustat(unsigned dev, struct ustat __user *ubuf);
/**  63 */ long dup2(unsigned int oldfd, unsigned int newfd);
/**  64 */ long getppid();
/**  65 */ long getpgrp();
/**  66 */ long setsid();
/**  67 */ long sigaction(int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact);
/**  68 */ long sgetmask();
/**  69 */ long ssetmask(int newmask);
/**  70 */ long setreuid(uid_t ruid, uid_t euid);
/**  71 */ long setregid(gid_t rgid, gid_t egid);
/**  72 */ long sigsuspend(old_sigset_t mask);
/**  73 */ long sigpending(old_sigset_t __user *uset);
/**  74 */ long sethostname(char __user *name, int len);
/**  75 */ long setrlimit(unsigned int resource, struct rlimit __user *rlim);
/**  76 */ long getrlimit(unsigned int resource, struct rlimit __user *rlim);
/**  77 */ long getrusage(int who, struct rusage __user *ru);
/**  78 */ long gettimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);
/**  79 */ long settimeofday(struct __kernel_old_timeval __user *tv, struct timezone __user *tz);
/**  80 */ long getgroups(int gidsetsize, gid_t __user *grouplist);
/**  81 */ long setgroups(int gidsetsize, gid_t __user *grouplist);
/**  82 */ long select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_old_timeval __user *tvp);
/**  83 */ long symlink(const char __user *oldname, const char __user *newname);
/**  84 */ long oldlstat(); // Missing definition
/**  85 */ long readlink(const char __user *path, char __user *buf, int bufsiz);
/**  86 */ long uselib(const char __user *library);
/**  87 */ long swapon(const char __user *specialfile, int swap_flags);
/**  88 */ long reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);
/**  89 */ long readdir(); // Missing definition
/**  90 */ long mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);
/**  91 */ long munmap(unsigned long addr, size_t len);
/**  92 */ long truncate(const char __user *path, long length);
/**  93 */ long ftruncate(unsigned int fd, off_t length);
/**  94 */ long fchmod(unsigned int fd, umode_t mode);
/**  95 */ long fchown(unsigned int fd, uid_t user, gid_t group);
/**  96 */ long getpriority(int which, int who);
/**  97 */ long setpriority(int which, int who, int niceval);
/**  98 */ long profil(); // Missing definition
/**  99 */ long statfs(const char __user *pathname, struct statfs __user *buf);
/** 100 */ long fstatfs(unsigned int fd, struct statfs __user *buf);
/** 101 */ long ioperm(unsigned long from, unsigned long num, int turn_on);
/** 102 */ long socketcall(int call, unsigned long __user *args);
/** 103 */ long syslog(int type, char __user *buf, int len);
/** 104 */ long setitimer(int which, struct __kernel_old_itimerval __user *value, struct __kernel_old_itimerval __user *ovalue);
/** 105 */ long getitimer(int which, struct __kernel_old_itimerval __user *value);
/** 106 */ long stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
/** 107 */ long lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
/** 108 */ long fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);
/** 109 */ long olduname(struct oldold_utsname __user *name);
/** 110 */ long iopl(unsigned int level);
/** 111 */ long vhangup();
/** 112 */ long idle(); // Missing definition
/** 113 */ long vm86old(struct vm86_struct __user *user_vm86);
/** 114 */ long wait4(pid_t upid, int __user *stat_addr, int options, struct rusage __user *ru);
/** 115 */ long swapoff(const char __user *specialfile);
/** 116 */ long sysinfo(struct sysinfo __user *info);
/** 117 */ long ipc(unsigned int call, int first, unsigned long second, unsigned long third, void __user *ptr, long fifth);
/** 118 */ long fsync(unsigned int fd);
/** 119 */ long sigreturn(); // Missing definition
/** 120 */ long clone(unsigned long clone_flags, unsigned long newsp);
/** 121 */ long setdomainname(char __user *name, int len);
/** 122 */ long uname(struct old_utsname __user *name);
/** 123 */ long modify_ldt(int  func , void __user * ptr , unsigned long  bytecount);
/** 124 */ long adjtimex(struct __kernel_timex __user *txc_p);
/** 125 */ long mprotect(unsigned long start, size_t len, unsigned long prot);
/** 126 */ long sigprocmask(int how, old_sigset_t __user *nset, old_sigset_t __user *oset);
/** 127 */ long create_module(); // Missing definition
/** 128 */ long init_module(void __user *umod, unsigned long len, const char __user *uargs);
/** 129 */ long delete_module(const char __user *name_user, unsigned int flags);
/** 130 */ long get_kernel_syms(); // Missing definition
/** 131 */ long quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);
/** 132 */ long getpgid(pid_t pid);
/** 133 */ long fchdir(unsigned int fd);
/** 134 */ long bdflush(); // Missing definition
/** 135 */ long sysfs(int option, unsigned long arg1, unsigned long arg2);
/** 136 */ long personality(unsigned int personality);
/** 137 */ long afs_syscall(); // Missing definition
/** 138 */ long setfsuid(uid_t uid);
/** 139 */ long setfsgid(gid_t gid);
/** 140 */ long _llseek(); // Missing definition
/** 141 */ long getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
/** 142 */ long _newselect(); // Missing definition
/** 143 */ long flock(unsigned int fd, unsigned int cmd);
/** 144 */ long msync(unsigned long start, size_t len, int flags);
/** 145 */ long readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
/** 146 */ long writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
/** 147 */ long getsid(pid_t pid);
/** 148 */ long fdatasync(unsigned int fd);
/** 149 */ long _sysctl(); // Missing definition
/** 150 */ long mlock(unsigned long start, size_t len);
/** 151 */ long munlock(unsigned long start, size_t len);
/** 152 */ long mlockall(int flags);
/** 153 */ long munlockall();
/** 154 */ long sched_setparam(pid_t pid, struct sched_param __user *param);
/** 155 */ long sched_getparam(pid_t pid, struct sched_param __user *param);
/** 156 */ long sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param);
/** 157 */ long sched_getscheduler(pid_t pid);
/** 158 */ long sched_yield();
/** 159 */ long sched_get_priority_max(int policy);
/** 160 */ long sched_get_priority_min(int policy);
/** 161 */ long sched_rr_get_interval(pid_t pid, struct __kernel_timespec __user *interval);
/** 162 */ long nanosleep(struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);
/** 163 */ long mremap(unsigned long addr, unsigned long old_len);
/** 164 */ long setresuid(uid_t ruid, uid_t euid, uid_t suid);
/** 165 */ long getresuid(uid_t __user *ruidp, uid_t __user *euidp, uid_t __user *suidp);
/** 166 */ long vm86(unsigned long cmd, unsigned long arg);
/** 167 */ long query_module(); // Missing definition
/** 168 */ long poll(struct pollfd __user *ufds, unsigned int nfds, int timeout_msecs);
/** 169 */ long nfsservctl(); // Missing definition
/** 170 */ long setresgid(gid_t rgid, gid_t egid, gid_t sgid);
/** 171 */ long getresgid(gid_t __user *rgidp, gid_t __user *egidp, gid_t __user *sgidp);
/** 172 */ long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
/** 173 */ long rt_sigreturn();
/** 174 */ long rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize);
/** 175 */ long rt_sigprocmask(int how, sigset_t __user *nset, sigset_t __user *oset, size_t sigsetsize);
/** 176 */ long rt_sigpending(sigset_t __user *uset, size_t sigsetsize);
/** 177 */ long rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct __kernel_timespec __user *uts, size_t sigsetsize);
/** 178 */ long rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);
/** 179 */ long rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);
/** 180 */ long pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
/** 181 */ long pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
/** 182 */ long chown(const char __user *filename, uid_t user, gid_t group);
/** 183 */ long getcwd(char __user *buf, unsigned long size);
/** 184 */ long capget(cap_user_header_t header, cap_user_data_t dataptr);
/** 185 */ long capset(cap_user_header_t header, const cap_user_data_t data);
/** 186 */ long sigaltstack(const stack_t __user *uss, stack_t __user *uoss);
/** 187 */ long sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count);
/** 188 */ long getpmsg(); // Missing definition
/** 189 */ long putpmsg(); // Missing definition
/** 190 */ long vfork();
/** 191 */ long ugetrlimit(); // Missing definition
/** 192 */ long mmap2(); // Missing definition
/** 193 */ long truncate64(const char __user *path, loff_t length);
/** 194 */ long ftruncate64(unsigned int fd, loff_t length);
/** 195 */ long stat64(const char __user *filename, struct stat64 __user *statbuf);
/** 196 */ long lstat64(const char __user *filename, struct stat64 __user *statbuf);
/** 197 */ long fstat64(unsigned long fd, struct stat64 __user *statbuf);
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
/** 217 */ long pivot_root(const char __user *new_root, const char __user *put_old);
/** 218 */ long mincore(unsigned long start, size_t len, unsigned char __user *vec);
/** 219 */ long madvise(unsigned long start, size_t len_in, int behavior);
/** 220 */ long getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
/** 221 */ long fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg);
/** 224 */ long gettid();
/** 225 */ long readahead(int fd, loff_t offset, size_t count);
/** 226 */ long setxattr(const char __user *pathname, const char __user *name, const void __user *value, size_t size, int flags);
/** 227 */ long lsetxattr(const char __user *pathname, const char __user *name, const void __user *value, size_t size, int flags);
/** 228 */ long fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags);
/** 229 */ long getxattr(const char __user *pathname, const char __user *name, void __user *value, size_t size);
/** 230 */ long lgetxattr(const char __user *pathname, const char __user *name, void __user *value, size_t size);
/** 231 */ long fgetxattr(int fd, const char __user *name, void __user *value, size_t size);
/** 232 */ long listxattr(const char __user *pathname, char __user *list, size_t size);
/** 233 */ long llistxattr(const char __user *pathname, char __user *list, size_t size);
/** 234 */ long flistxattr(int fd, char __user *list, size_t size);
/** 235 */ long removexattr(const char __user *pathname, const char __user *name);
/** 236 */ long lremovexattr(const char __user *pathname, const char __user *name);
/** 237 */ long fremovexattr(int fd, const char __user *name);
/** 238 */ long tkill(pid_t pid, int sig);
/** 239 */ long sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count);
/** 240 */ long futex(u32 __user *uaddr, int op, u32 val, const struct __kernel_timespec __user *utime, u32 __user *uaddr2, u32 val3);
/** 241 */ long sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
/** 242 */ long sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
/** 243 */ long set_thread_area(struct user_desc __user *u_info);
/** 244 */ long get_thread_area(struct user_desc __user *u_info);
/** 245 */ long io_setup(unsigned nr_events, aio_context_t __user *ctxp);
/** 246 */ long io_destroy(aio_context_t ctx);
/** 247 */ long io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout);
/** 248 */ long io_submit(aio_context_t ctx_id, long nr, struct iocb __user *__user *iocbpp);
/** 249 */ long io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);
/** 250 */ long fadvise64(int fd, loff_t offset, size_t len, int advice);
/** 252 */ long exit_group(int error_code);
/** 253 */ long lookup_dcookie(); // Missing definition
/** 254 */ long epoll_create(int size);
/** 255 */ long epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event);
/** 256 */ long epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout);
/** 257 */ long remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
/** 258 */ long set_tid_address(int __user *tidptr);
/** 259 */ long timer_create(const clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user *created_timer_id);
/** 260 */ long timer_settime(timer_t timer_id, int flags, const struct __kernel_itimerspec __user *new_setting, struct __kernel_itimerspec __user *old_setting);
/** 261 */ long timer_gettime(timer_t timer_id, struct __kernel_itimerspec __user *setting);
/** 262 */ long timer_getoverrun(timer_t timer_id);
/** 263 */ long timer_delete(timer_t timer_id);
/** 264 */ long clock_settime(const clockid_t which_clock);
/** 265 */ long clock_gettime(const clockid_t which_clock);
/** 266 */ long clock_getres(const clockid_t which_clock, struct __kernel_timespec __user *tp);
/** 267 */ long clock_nanosleep(const clockid_t which_clock, int flags);
/** 268 */ long statfs64(const char __user *pathname, size_t sz, struct statfs64 __user *buf);
/** 269 */ long fstatfs64(unsigned int fd, size_t sz, struct statfs64 __user *buf);
/** 270 */ long tgkill(pid_t tgid, pid_t pid, int sig);
/** 271 */ long utimes(char __user *filename, struct __kernel_old_timeval __user *utimes);
/** 272 */ long fadvise64_64(int fd, loff_t offset, loff_t len, int advice);
/** 273 */ long vserver(); // Missing definition
/** 274 */ long mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned int flags);
/** 275 */ long get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
/** 276 */ long set_mempolicy(int mode, const unsigned long __user *nmask, unsigned long maxnode);
/** 277 */ long mq_open(const char __user *u_name, int oflag, umode_t mode, struct mq_attr __user *u_attr);
/** 278 */ long mq_unlink(const char __user *u_name);
/** 279 */ long mq_timedsend(mqd_t mqdes, const char __user *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *u_abs_timeout);
/** 280 */ long mq_timedreceive(mqd_t mqdes, char __user *u_msg_ptr, size_t msg_len, unsigned int __user *u_msg_prio, const struct __kernel_timespec __user *u_abs_timeout);
/** 281 */ long mq_notify(mqd_t mqdes, const struct sigevent __user *u_notification);
/** 282 */ long mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *u_mqstat, struct mq_attr __user *u_omqstat);
/** 283 */ long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);
/** 284 */ long waitid(int which, pid_t upid, struct siginfo __user *infop, int options, struct rusage __user *ru);
/** 286 */ long add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t ringid);
/** 287 */ long request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);
/** 288 */ long keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
/** 289 */ long ioprio_set(int which, int who, int ioprio);
/** 290 */ long ioprio_get(int which, int who);
/** 291 */ long inotify_init();
/** 292 */ long inotify_add_watch(int fd, const char __user *pathname, u32 mask);
/** 293 */ long inotify_rm_watch(int fd, __s32 wd);
/** 294 */ long migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *old_nodes, const unsigned long __user *new_nodes);
/** 295 */ long openat(int dfd, const char __user *filename, int flags, umode_t mode);
/** 296 */ long mkdirat(int dfd, const char __user *pathname, umode_t mode);
/** 297 */ long mknodat(int dfd, const char __user *filename, umode_t mode, unsigned int dev);
/** 298 */ long fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
/** 299 */ long futimesat(int dfd, const char __user *filename, struct __kernel_old_timeval __user *utimes);
/** 300 */ long fstatat64(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag);
/** 301 */ long unlinkat(int dfd, const char __user *pathname, int flag);
/** 302 */ long renameat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname);
/** 303 */ long linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
/** 304 */ long symlinkat(const char __user *oldname, int newdfd, const char __user *newname);
/** 305 */ long readlinkat(int dfd, const char __user *pathname, char __user *buf, int bufsiz);
/** 306 */ long fchmodat(int dfd, const char __user *filename, umode_t mode);
/** 307 */ long faccessat(int dfd, const char __user *filename, int mode);
/** 308 */ long pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_timespec __user *tsp, void __user *sig);
/** 309 */ long ppoll(struct pollfd __user *ufds, unsigned int nfds, struct __kernel_timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize);
/** 310 */ long unshare(unsigned long unshare_flags);
/** 311 */ long set_robust_list(struct robust_list_head __user *head, size_t len);
/** 312 */ long get_robust_list(int pid, struct robust_list_head __user *__user *head_ptr, size_t __user *len_ptr);
/** 313 */ long splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
/** 314 */ long sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);
/** 315 */ long tee(int fdin, int fdout, size_t len, unsigned int flags);
/** 316 */ long vmsplice(int fd, const struct iovec __user *uiov, unsigned long nr_segs, unsigned int flags);
/** 317 */ long move_pages(pid_t pid, unsigned long nr_pages, const void __user *__user *pages, const int __user *nodes, int __user *status, int flags);
/** 318 */ long getcpu(unsigned __user *cpup, unsigned __user *nodep, struct getcpu_cache __user *unused);
/** 319 */ long epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);
/** 320 */ long utimensat(int dfd, const char __user *filename, struct __kernel_timespec __user *utimes, int flags);
/** 321 */ long signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);
/** 322 */ long timerfd_create(int clockid, int flags);
/** 323 */ long eventfd(unsigned int count);
/** 324 */ long fallocate(int fd, int mode, loff_t offset, loff_t len);
/** 325 */ long timerfd_settime(int ufd, int flags, const struct __kernel_itimerspec __user *utmr, struct __kernel_itimerspec __user *otmr);
/** 326 */ long timerfd_gettime(int ufd, struct __kernel_itimerspec __user *otmr);
/** 327 */ long signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
/** 328 */ long eventfd2(unsigned int count, int flags);
/** 329 */ long epoll_create1(int flags);
/** 330 */ long dup3(unsigned int oldfd, unsigned int newfd, int flags);
/** 331 */ long pipe2(int __user *fildes, int flags);
/** 332 */ long inotify_init1(int flags);
/** 333 */ long preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
/** 334 */ long pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
/** 335 */ long rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t __user *uinfo);
/** 336 */ long perf_event_open(struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
/** 337 */ long recvmmsg(int fd, struct mmsghdr __user *mmsg, unsigned int vlen, unsigned int flags, struct __kernel_timespec __user *timeout);
/** 338 */ long fanotify_init(unsigned int flags, unsigned int event_f_flags);
/** 339 */ long fanotify_mark(int fanotify_fd, unsigned int flags, __u64 mask, int dfd, const char __user *pathname);
/** 340 */ long prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim);
/** 341 */ long name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, void __user *mnt_id, int flag);
/** 342 */ long open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags);
/** 343 */ long clock_adjtime(const clockid_t which_clock, struct __kernel_timex __user *utx);
/** 344 */ long syncfs(int fd);
/** 345 */ long sendmmsg(int fd, struct mmsghdr __user *mmsg, unsigned int vlen, unsigned int flags);
/** 346 */ long setns(int fd, int flags);
/** 347 */ long process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
/** 348 */ long process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
/** 349 */ long kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
/** 350 */ long finit_module(int fd, const char __user *uargs, int flags);
/** 351 */ long sched_setattr(pid_t pid, struct sched_attr __user *uattr, unsigned int flags);
/** 352 */ long sched_getattr(pid_t pid, struct sched_attr __user *uattr, unsigned int usize, unsigned int flags);
/** 353 */ long renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
/** 354 */ long seccomp(unsigned int op, unsigned int flags, void __user *uargs);
/** 355 */ long getrandom(char __user *ubuf, size_t len, unsigned int flags);
/** 356 */ long memfd_create(const char __user *uname, unsigned int flags);
/** 357 */ long bpf(int cmd, union bpf_attr __user *uattr, unsigned int size);
/** 358 */ long execveat(int fd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
/** 359 */ long socket(int family, int type, int protocol);
/** 360 */ long socketpair(int family, int type, int protocol, int __user *usockvec);
/** 361 */ long bind(int fd, struct sockaddr __user *umyaddr, int addrlen);
/** 362 */ long connect(int fd, struct sockaddr __user *uservaddr, int addrlen);
/** 363 */ long listen(int fd, int backlog);
/** 364 */ long accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags);
/** 365 */ long getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen);
/** 366 */ long setsockopt(int fd, int level, int optname, char __user *optval, int optlen);
/** 367 */ long getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
/** 368 */ long getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
/** 369 */ long sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len);
/** 370 */ long sendmsg(int fd, struct user_msghdr __user *msg, unsigned int flags);
/** 371 */ long recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
/** 372 */ long recvmsg(int fd, struct user_msghdr __user *msg, unsigned int flags);
/** 373 */ long shutdown(int fd, int how);
/** 374 */ long userfaultfd(int flags);
/** 375 */ long membarrier(int cmd, unsigned int flags, int cpu_id);
/** 376 */ long mlock2(unsigned long start, size_t len, int flags);
/** 377 */ long copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
/** 378 */ long preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
/** 379 */ long pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
/** 380 */ long pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey);
/** 381 */ long pkey_alloc(unsigned long flags, unsigned long init_val);
/** 382 */ long pkey_free(int pkey);
/** 383 */ long statx(int dfd, const char __user *filename, unsigned flags, unsigned int mask, struct statx __user *buffer);
/** 384 */ long arch_prctl(int option, unsigned long arg2);
/** 385 */ long io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout, const struct __aio_sigset __user *usig);
/** 386 */ long rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig);
/** 393 */ long semget(key_t key, int nsems, int semflg);
/** 394 */ long semctl(int semid, int semnum, int cmd, unsigned long arg);
/** 395 */ long shmget(key_t key, size_t size, int shmflg);
/** 396 */ long shmctl(int shmid, int cmd, struct shmid_ds __user *buf);
/** 397 */ long shmat(int shmid, char __user *shmaddr, int shmflg);
/** 398 */ long shmdt(char __user *shmaddr);
/** 399 */ long msgget(key_t key, int msgflg);
/** 400 */ long msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);
/** 401 */ long msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);
/** 402 */ long msgctl(int msqid, int cmd, struct msqid_ds __user *buf);
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
/** 424 */ long pidfd_send_signal(int pidfd, int sig, siginfo_t __user *info, unsigned int flags);
/** 425 */ long io_uring_setup(u32 entries, struct io_uring_params __user *params);
/** 426 */ long io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void __user *argp, size_t argsz);
/** 427 */ long io_uring_register(unsigned int fd, unsigned int opcode, void __user *arg, unsigned int nr_args);
/** 428 */ long open_tree(int dfd, const char __user *filename, unsigned flags);
/** 429 */ long move_mount(int from_dfd, const char __user *from_pathname, int to_dfd, const char __user *to_pathname, unsigned int flags);
/** 430 */ long fsopen(const char __user *_fs_name, unsigned int flags);
/** 431 */ long fsconfig(int fd, unsigned int cmd, const char __user *_key, const void __user *_value, int aux);
/** 432 */ long fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags);
/** 433 */ long fspick(int dfd, const char __user *path, unsigned int flags);
/** 434 */ long pidfd_open(pid_t pid, unsigned int flags);
/** 435 */ long clone3(struct clone_args __user *uargs, size_t size);
/** 436 */ long close_range(unsigned int fd, unsigned int max_fd, unsigned int flags);
/** 437 */ long openat2(int dfd, const char __user *filename, struct open_how __user *how, size_t usize);
/** 438 */ long pidfd_getfd(int pidfd, int fd, unsigned int flags);
/** 439 */ long faccessat2(int dfd, const char __user *filename, int mode, int flags);
/** 440 */ long process_madvise(int pidfd, const struct iovec __user *vec, size_t vlen, int behavior, unsigned int flags);
/** 441 */ long epoll_pwait2(int epfd, struct epoll_event __user *events, int maxevents, const struct __kernel_timespec __user *timeout, const sigset_t __user *sigmask, size_t sigsetsize);
/** 442 */ long mount_setattr(int dfd, const char __user *path, unsigned int flags, struct mount_attr __user *uattr, size_t usize);
/** 443 */ long quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id, void __user *addr);
/** 444 */ long landlock_create_ruleset(const struct landlock_ruleset_attr __user *const attr, const size_t size, const __u32 flags);
/** 445 */ long landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type, const void __user *const rule_attr, const __u32 flags);
/** 446 */ long landlock_restrict_self(const int ruleset_fd, const __u32 flags);
/** 447 */ long memfd_secret(unsigned int flags);
/** 448 */ long process_mrelease(int pidfd, unsigned int flags);
/** 449 */ long futex_waitv(struct futex_waitv __user *waiters, unsigned int nr_futexes, unsigned int flags, struct __kernel_timespec __user *timeout, clockid_t clockid);
/** 450 */ long set_mempolicy_home_node(unsigned long start, unsigned long len, unsigned long home_node, unsigned long flags);
/** 451 */ long cachestat(unsigned int fd, struct cachestat_range __user *cstat_range, struct cachestat __user *cstat, unsigned int flags);
/** 452 */ long fchmodat2(int dfd, const char __user *filename, umode_t mode, unsigned int flags);
/** 453 */ long map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags);
/** 454 */ long futex_wake(void __user *uaddr, unsigned long mask, int nr, unsigned int flags);
/** 455 */ long futex_wait(void __user *uaddr, unsigned long val, unsigned long mask, unsigned int flags, struct __kernel_timespec __user *timeout, clockid_t clockid);
/** 456 */ long futex_requeue(struct futex_waitv __user *waiters, unsigned int flags, int nr_wake, int nr_requeue);
/** 457 */ long statmount(const struct mnt_id_req __user *req, struct statmount __user *buf, size_t bufsize, unsigned int flags);
/** 458 */ long listmount(const struct mnt_id_req __user *req, u64 __user *mnt_ids, size_t nr_mnt_ids, unsigned int flags);
/** 459 */ long lsm_get_self_attr(unsigned int attr, struct lsm_ctx __user *ctx, u32 __user *size, u32 flags);
/** 460 */ long lsm_set_self_attr(unsigned int attr, struct lsm_ctx __user *ctx, u32 size, u32 flags);
/** 461 */ long lsm_list_modules(u64 __user *ids, u32 __user *size, u32 flags);
/** 462 */ long mseal(unsigned long start, size_t len, unsigned long flags);
/** 463 */ long setxattrat(); // Missing definition
/** 464 */ long getxattrat(); // Missing definition
/** 465 */ long listxattrat(); // Missing definition
/** 466 */ long removexattrat(); // Missing definition
