#!/bin/bash -e

source "$(dirname "$0")/test-functions.inc"
create_files "$1"
shift

# TODO
export UBSAN_OPTIONS=detect_leaks=0

input="$(seq 1000 | tr -d " \n")"

cd "$test_cwd"
echo "$input" | "$@"

echo "Done"
