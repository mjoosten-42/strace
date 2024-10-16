#!/bin/bash

file="src/syscall.c"
systemheader="/usr/include/x86_64-linux-gnu/asm/unistd_64.h"

cat > $file << EOF
const char *syscall_name(int number) {
	static const char *syscalls[] = {
EOF
 
while read -r line; do
	number=$(echo "$line" | cut -d ' ' -f3)

	if [[ $number =~ ^[0-9]+$ ]] ; then
		name=$(echo "$line" | cut -d ' ' -f2 | cut -d '_' -f4-)
		
		echo -e "\t\t[$number] = \"$name\"," >> "$file"
	fi
done < "$systemheader"

cat >> $file << EOF
	};

	return syscalls[number];
}

EOF

