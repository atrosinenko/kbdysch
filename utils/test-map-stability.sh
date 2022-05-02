#!/bin/bash -e

input="$(seq 1000 | tr -d " \n")"

for i in `seq 10`; do
  echo "Iteration $i..."
  rm -f /tmp/afl-map-data
  echo "$input" | setarch "$(uname -m)" --addr-no-randomize afl-showmap -o /tmp/afl-map-data -- "$@"
  test -f /tmp/afl-map-data

  cur_md5=$(md5sum /tmp/afl-map-data | cut -f1 -d" ")
  if [ $i = 1 ]; then
    ref_md5="$cur_md5"
  fi
  if [ "$ref_md5" != "$cur_md5" ]; then
    echo "Maps differ at iteration $i"
    exit 1
  fi
done

echo "Done"
