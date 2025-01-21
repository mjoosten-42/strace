#/bin/bash

grep < "$1" -v '^[#$]' | grep -v '^$' | awk '{ print($1, $3, $4) }'
