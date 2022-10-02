#!/bin/bash

injector="$1"
harness="$2"
test_input="$3.in"
test_ref_output="$3.out"

temp=$(mktemp -u /tmp/kbdysch-mutator-test.XXXXXX)

export INJECTOR_TEST_CASE="$test_input"
export INJECTOR_PRINT=1

# Variables have form "[NAME:some value]"
get_variable() {
  local var_name="$1"
  grep -P --only-matching "(?<=\[${var_name}:).*(?=\])" < "$test_input"
}

begin_marker="$(get_variable BEGIN)"
end_marker="$(get_variable END)"
choose_marker="$(get_variable CHOOSE)"
requested_env="$(get_variable ENV)"

# Multiple variables can be exported
[ -n "$requested_env" ] && export $requested_env

postprocess() {
  args=()
  args+=(-e 's/[ \t]+/ /g') # Normalize whitespace
  args+=(-e '/\[.*\]/ d')   # Remove any "[...]" text
  if [ $is_ref = n ]; then
    [ -n "$begin_marker" ]  && args+=(-e "1,/${begin_marker}/ d")
    [ -n "$end_marker" ]    && args+=(-e "/${end_marker}/ Q")
    [ -n "$choose_marker" ] && args+=(-e "/${choose_marker}/ ! d")
  fi
  sed -E "${args[@]}"
}

LD_PRELOAD="$injector" "$harness" < "$test_input" > "$temp.real" 2>&1

is_ref=n postprocess < "$temp.real"       > "$temp.real-normalized"
is_ref=y postprocess < "$test_ref_output" > "$temp.ref-normalized"

if diff "$temp.real-normalized" "$temp.ref-normalized"; then
  echo "Output is correct"
  rm "$temp".{real,real-normalized,ref-normalized}
else
  echo "Output is incorrect, see $temp.real-normalized (reference is $temp.ref-normalized)"
  exit 1
fi
