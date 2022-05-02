#!/bin/bash -e

# TODO
export UBSAN_OPTIONS=detect_leaks=0

input="$(seq 1000 | tr -d " \n")"

echo "$input" | "$@"

echo "Done"
