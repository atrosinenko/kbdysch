declare -a files_to_delete

test_cwd="$PWD/temp-test-cwd"

create_files() {
  local files="$1"

  mkdir "$test_cwd" # Fail if exists
  pushd "$test_cwd"

  for description in $files; do
    IFS="=" read file_name file_size <<< "$description"
    files_to_delete+=("$file_name")
    fallocate -l "$file_size" "$file_name"
  done

  popd

  trap delete_files EXIT
}

delete_files() {
  pushd "$test_cwd"
  rm -f -- "${files_to_delete[@]}"
  popd
  rmdir "$test_cwd" # Fail if not empty
}
