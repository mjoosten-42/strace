#!/bin/bash

file="prototypes.c"
systemheader="/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
headers=""
prototypes=""

while read -r line; do
	number=$(echo "$line" | cut -d ' ' -f3)

	if [[ $number =~ ^[0-9]+$ ]] ; then
		name=$(echo "$line" | cut -d ' ' -f2 | cut -d '_' -f4-)

		if [[ ! -z $1 ]]; then
			name="$1"
		fi

		if ! man 2 $name > /dev/null 2>&1; then
			continue
		fi

		synopsis="$(man 2 $name | sed -n '/^SYNOPSIS/,/^[A-Z]/p' | sed '$d')"
		includes="$(echo "$synopsis" | grep '#include' | awk '{ $1=$1; print }'	| cut -d ' ' -f -2)"

		s1="$(echo "$synopsis" | grep "$name(" -A 1 -m 1)"
		s2="$(echo "$s1" | tr -d '\n' | xargs | sed 's/; /;\n/g')"
		s3="$(echo "$s2" | grep "[\* ]$name(")"
	
		if [[ $2 == debug ]]; then
			echo -e "synopsis: [\n$synopsis\n]"
			echo -e "s1      : [\n$s1\n]"
			echo -e "s2      : [\n$s2\n]"
			echo -e "s3      : [\n$s3\n]"
		fi

		IFS=$'\n'; array=( $(echo "$s3") )

		prototype=""
		max_length=0

		for prot in "${array[@]}"; do
			if [[ ${#prot} -gt $max_length ]]; then
				prototype="$prot"
				max_length=${#prot}
			fi
		done

		if [[ -z "$prototype" ]]; then
			continue
		fi

		echo "$prototype"

		prototypes+="$prototype"
		prototypes+=$'\n'

		headers+="$includes"
		headers+=$'\n'

		if [[ $2 == debug ]]; then
			break;
		fi
	fi

done < "$systemheader"

headers="$(echo "$headers" | sort | uniq)"

echo -n > "$file"
echo "$headers" >> "$file"
echo >> "$file"
echo "$prototypes" >> "$file"

