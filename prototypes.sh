#!/bin/bash

syscall=${1:-read}
all="$(man 2 $syscall)"

start="$(echo "$all" | grep -n 'SYNOPSIS' | cut -d ':' -f1)"
end="$(echo "$all" | grep -n 'DESCRIPTION' | cut -d ':' -f1)"
section="$(echo "$all" | head -n $(($end - 1)) | tail -n $(($end - $start - 1)))"

# oh no
echo $section | grep -E "\s+(.*)\s+\*?$syscall\([^\)]*\);"
