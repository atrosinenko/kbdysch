#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/mutator-interface.h"

static const int MAX_INPUT_OPS = 25;

static void check_part_is_clean(struct fuzzer_state *state, int part, const char *name)
{
  if (kernel_scan_for_files(state, part) != 0) {
    kernel_dump_file_names(state);
    fprintf(stderr, "Error: the partition %s has some files, this is not supported in comparison mode, exiting.\n", name);
    abort();
  }
}

int main(int argc, const char *argv[])
{
  struct fuzzer_state * const state = create_state(argc, argv, NULL);

  mutator_init();

  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_WITH_ARGS("<kernel command line> <fstype>")
        USAGE_THEN_DO  ("Issue operations on a single FS image (PATCH op can be used)")
        USAGE_WITH_ARGS("<kernel command line> <fstype1> <fstype2> ...")
        USAGE_THEN_DO  ("Run in comparison mode (PATCH op is disabled)"));

  if (is_native_invoker(state)) {
    kernel_configure_diskless(state, "." /* current directory */);
  } else {
    int part_count = argc - 2;
    if (part_count == 0) {
      fprintf(stderr, "You have configured LKL invoker without any partition, exiting.\n");
      exit(1);
    }
    for (int i = 0; i < part_count; ++i) {
      kernel_setup_disk(state, argv[2 + i], argv[2 + i]);
    }
    kernel_boot(state, argv[1]);
    if (part_count > 1) {
      for (int i = 0; i < part_count; ++i) {
        check_part_is_clean(state, i, argv[2 + i]);
      }
    } else {
      int file_count = kernel_scan_for_files(state, 0);
      if (file_count > 0) {
        kernel_dump_file_names(state);
        fprintf(stderr, "Found %d files on %s. This is OK since not in comparison mode.\n", file_count, argv[2 + 0]);
      }
    }
  }

  kernel_dump_file_contents(state, "/proc/mounts");
  // TODO: Show detailed info such as /proc/fs/ext4/*/options

  res_load_whole_stdin(state);

  if (setjmp(*res_get_stopper_env(state)) == 0) {
    for (int block_index = 0; block_index < MAX_INPUT_OPS; ++block_index) {
      mutator_write_trim_offset(res_get_cur_offset(state));

      exit_if_too_many_errors(state);
      skip_block_if_requested(state, block_index);
      size_t decoded_bytes = do_invoke(state, block_index);
      align_next_block(state, block_index, decoded_bytes);
    }
  }
  print_summary_at_exit(state);

  return 0;
}
