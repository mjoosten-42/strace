#!/bin/bash

if [ -z $1 ]; then
	echo "Provide a table"
	exit
fi

while read -r line; do
	nr=$(echo $line | cut -d ' ' -f1)
	name=$(echo $line | cut -d ' ' -f3) 
	entry=$(echo $line | cut -d ' ' -f4) 

	if [ ! -z $2 ]; then
		name=$2
	fi

	pat='^SYSCALL_DEFINE\d\('$name'[,)]'
	def="$(grep -P "$pat" -r ~/Desktop/linux/ --exclude-dir=arch --include '*.c' -n)"

	echo -n "/** $(printf %3d $nr) */ long $name("

	if [ -z "$def" ]; then
		def="$(grep -P "$pat" -r ~/Desktop/linux/arch/x86/kernel --include '*.c' -n)"
	fi

	if [ -z "$def" ]; then
		echo "); // Missing definition"
		continue
	fi

	file="$(echo $def | cut -d ':' -f1)"
	number=$(echo $def | cut -d ':' -f2)

	# multiline definition
	while [[ $def != *")"* ]]; do
		((number++))

		pat="${number}q;d"
		next="$(sed $pat $file)"
		def="$def""$next"
	done

	def="$(echo "$def" | tr '\t' ' ' | tr -s ' ' | tr -d ')')"
	args="$(echo "$def" | cut -d '(' -f2)"

	IFS=',' read -r -a array <<< "$args"

	prototype=""

	for ((i=1; i<${#array[@]}; i+=2)); do
		prototype+="${array[i]}${array[i+1]},"
	done

	prototype="${prototype%,}"
	prototype="$(echo "$prototype" | sed 's/* /*/g' | sed 's/^ //g')"
	prototype+=");"

	echo "$prototype"

	if [ ! -z $2 ]; then
		exit
	fi

done <<< "$(tr -s ' ' < $1)"

