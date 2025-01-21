#!/bin/bash

while read -r line
do
	entry="$(echo "$line" | cut -d ' ' -f3)"
	proto="$(grep "$entry" syscalls.h)"

	if [ -z "$proto" ]; then
		echo "$line"
	fi
done < "$1"

