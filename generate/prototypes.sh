#!/bin/bash

systemheader="/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
headers=""
prototypes=()
exceptions=()
exceptions[ 13]="int rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t);"
exceptions[ 14]="int rt_sigprocmask(int, const sigset_t *, sigset_t *, size_t);"
exceptions[ 15]="int rt_sigreturn(...);"
exceptions[ 17]="ssize_t pread64(unsigned int fd, char *buf, size_t count, loff_t pos);"
exceptions[ 18]="ssize_t pwrite64(unsigned int fd, const char *buf, size_t count, loff_t pos);"
exceptions[ 22]="int pipe(int pipefds[2]);"
exceptions[127]="int rt_sigpending(sigset_t *set, size_t sigsetsize);"
exceptions[128]="int rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const struct _kernel_timespec *uts, size_t sigsetsize);"
exceptions[129]="int rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo);"
exceptions[130]="int rt_sigsuspend(sigset_t *unewset, size_t sigsetsize);"
exceptions[169]="int reboot(int op);"
exceptions[214]="int epoll_ctl_old(int, int, struct e_poll_event *);"
exceptions[215]="int epoll_wait_old(int, struct e_poll_event *, int);"
exceptions[221]="int fadvise64(int fd, loff_t offset, size_t len, int advice);"
exceptions[262]="int newfstatat(int dfd, const char *filename, struct stat *statbuf, int flag);"
exceptions[270]="int pselect6(int, fd_set *, fd_set *, fd_set *, struct __kernel_timespec *, void *);"
exceptions[289]="int signalfd4(int ufd, sigset_t *user_mask, size_t sizemask, int flags);"
exceptions[290]="int eventfd2(unsigned int count, int flags);"
exceptions[302]="int prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);"
exceptions[310]="int process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);"
exceptions[311]="int process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);"

while read -r line; do
	number=$(echo "$line" | cut -d ' ' -f3)

	if [[ ! -z $1 && $number != $1 ]]; then
		continue
	fi

	if [[ $number =~ ^[0-9]+$ ]] ; then
		prototype=""
	
		if [[ -v exceptions[$number] ]]; then
			prototype="${exceptions[$number]}"
		else
			name=$(echo "$line" | cut -d ' ' -f2 | cut -d '_' -f4-)

			if ! man 2 $name > /dev/null 2>&1; then
				continue
			fi

			content="$(man 2 $name)"

			if echo "$content" | grep -q "UNIMPLEMENTED"; then
				prototype="int $name(); /* Not implemented */"
			else
				synopsis="$(echo "$content" | sed -n '/^SYNOPSIS/,/^[A-Z]/p' | sed '$d')"
				includes="$(echo "$synopsis" | grep '#include' | awk '{ $1=$1; print }'	| cut -d ' ' -f -2)"
			
				if [[ $2 == debug ]]; then
					s1="$(echo "$synopsis" | grep "$name(" -A 2 -m 1)"
					s2="$(echo "$s1" | tr -d '\n' | xargs | sed 's/; /;\n/g')"
					s3="$(echo "$s2" | grep "[\*_ ]$name(" | sed "s/_$name/$name/g")"
	
					echo -e "synopsis: [\n$synopsis\n]"
					echo -e "s1      : [\n$s1\n]"
					echo -e "s2      : [\n$s2\n]"
					echo -e "s3      : [\n$s3\n]"
				fi

				#IFS=$'\n'; array=( $(echo "$s3") )
				IFS=$'\n'; array=( $(echo "$synopsis" | grep "$name(" -A 2 -m 1 | tr -d	'\n' | xargs | sed 's/; /;\n/g' | grep "[\*_ ]$name(" |	sed	"s/_$name/$name/g" | sed 's/\s*\/\*.*\*\/\s*//') )
	
				len=0

				for item in "${array[@]}"; do
					if [[ ${#item} -gt $len ]]; then
						prototype="$item"
						len=${#item}
					fi
				done
			fi
		fi

		echo "$number: $prototype" >&2

		prototypes+=("/** $(printf %3s $number) */ $prototype")

		headers+="$includes"
		headers+=$'\n'
	fi

done < "$systemheader"

headers="$(echo "$headers" | sort | uniq)"
headers="${headers:1}"

echo "$headers"
echo

for prototype in "${prototypes[@]}"; do
	echo "$prototype"
done

echo

