#!/bin/bash

# Path to your JSON file
json_file="syscalls.json"

# C file to output
output_file="src/syscall.c"

# Start by including the header and initializing an array
cat << EOF > "$output_file"
#include "syscall.h"

const syscall_info *get_syscall_info(int nr) {
	static const syscall_info syscalls[] = {
EOF

syscalls=$(jq -c '. | sort_by(.nr) | map({name: .name, nr: .nr, args: [.arg0, .arg1, .arg2, .arg3, .arg4, .arg5]})' "$json_file")

# Loop through each syscall in the JSON
echo "$syscalls" | jq -c '.[]' | while read -r syscall; do
	# Extract information from each syscall
    nr=$(echo "$syscall" | jq -r '.nr')
    name=$(echo "$syscall" | jq -r '.name')
    args=$(echo "$syscall" | jq -r '.args')
    argc=$(echo "$args" | jq -r '[.[] | select(. != "")] | length')

	echo -en "$nr: $name               \r"

	cat << EOF >> "$output_file"
		{ $nr, "$name", $argc, { 
EOF

	for i in $(seq 0 $(($argc - 1))); do
        arg=$(echo "$args" | jq -r ".[$i]")
		# Determine type and size for each argument (simplified for demonstration)
		case "$arg" in
			*"char *"*)
				type="%s"
				size=8
				;;
			*"*"*)
				type="%p"
				size=8
				;;
			*"int"*)
				type="%i"
				size=4
				;;
			*"char *"*)
				type="%s"
				size=1
				;;
			*"size_t"*)
				type="%lu"
				size=8
				;;
			*)
				type="%lu"
				size=8
				;;
		esac

		if [[ $(echo "$arg" | tr -cd '*' | wc -c) -ge 2 ]]; then
			type="%p"
		fi

		cat << EOF >> "$output_file"
		{ "$type", $size },	
EOF

    done

	echo -e "\t\t} }," >> "$output_file"
done

cat << EOF >> "$output_file"
	};

	return &syscalls[nr];
}

EOF

# Print success message
echo "C array of syscalls has been generated in $output_file."
