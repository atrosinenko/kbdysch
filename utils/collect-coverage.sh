#!/bin/bash -e

if [ $# -lt 2 ]; then
  echo "Usage: $0 'harness command line' dir1 [dir2 dir3 ...]"
  echo "Environment variables:"
  echo "  LLVM_PROFDATA - llvm-profdata executable to use"
  echo "  OUT_DIR       - output/scratch directory"
  echo "  BATCH_SIZE    - how many profiles to aggregate at once (disk space / time tradeoff)"
  exit 1
fi

command_line=($1)
shift

llvm_profdata="${LLVM_PROFDATA:-llvm-profdata}"
outdir="${OUT_DIR:-/tmp/kbdysch-prof}"
batch_size="${BATCH_SIZE:-200}"
mkdir $outdir

execute_harness() {
  local i="$1"
  local input="$2"

  export LLVM_PROFILE_FILE="$outdir/tmp-$i.profraw"
  "${command_line[@]}" < "$input"
  unset LLVM_PROFILE_FILE
}

aggregate_batch() {
  local i="$1"
  local out_file="$outdir/aggregated-$i.profdata"

  echo "Aggregating to $out_file..."
  $llvm_profdata merge $outdir/tmp-*.profraw -output "$out_file"
  rm $outdir/tmp-*.profraw
}

collect_profiles() {
  local i=1
  local dir input

  for dir in "$@"; do
    for input in $dir/*+cov; do
      execute_harness $i "$input"
      [ $((i % batch_size)) = 0 ] && aggregate_batch $i
      i=$((i+1))
    done
    aggregate_batch $i
  done

  local result_file="$outdir/result.profdata"
  $llvm_profdata merge $outdir/aggregated-*.profdata -output "$result_file"
  echo "Now you can use something like"
  echo ""
  echo "    llvm-cov show --instr-profile $result_file path/to/instrumented/liblkl.so -output-dir /tmp/kbdysch-report -format html"
  echo ""
  echo "to generate coverage report or use $result_file as an argument to KBDYSCH_PROFDATA CMake option."
}

collect_profiles "$@"

