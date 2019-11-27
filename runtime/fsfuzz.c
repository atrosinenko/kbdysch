#include "kbdysch.h"
#include "invoker-utils.h"

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
  struct fuzzer_state * const state = create_state(argc, argv);

  show_help_and_exit_if_needed(
        argc, argv,
        USAGE_RUN_NATIVELY
        USAGE_WITH_ARGS("<kernel command line> <fstype>")
        USAGE_THEN_DO  ("Issue operations on a single FS image (PATCH op can be used)")
        USAGE_WITH_ARGS("<kernel command line> <fstype1> <fstype2> ...")
        USAGE_THEN_DO  ("Run in comparison mode (PATCH op is disabled)"));

  if (is_native_invoker(state)) {
    kernel_setup_dummy_disk(state);
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

  res_load_whole_stdin(state);

  if (setjmp(*res_get_stopper_env(state)) == 0) {
    for (int op_num = 0; op_num < MAX_INPUT_OPS; ++op_num) {
      size_t old_offset = res_get_cur_offset(state);
      uint8_t opc = res_get_u8(state);
      fprintf(stderr, "==> [%03d] Decoding at offset %ld, opc = %u...\n", op_num, res_get_cur_offset(state), opc);

      invoke_next_op(state, opc);
      size_t decoded_bytes = res_get_cur_offset(state) - old_offset;

      size_t consume_total = 1;
      while (consume_total < decoded_bytes) {
        consume_total *= 2;
      }
      res_skip_bytes(state, consume_total - decoded_bytes);

      fprintf(stderr, "<== [%03d] Decoded %zu bytes, consuming %zu in total.\n", op_num, decoded_bytes, consume_total);
    }
  }
  size_t processed = res_get_cur_offset(state);
  size_t total = res_get_input_length(state);
  fprintf(stderr, "--> Decoded %ld bytes (%ld bytes left).\n", processed, total - processed);

  return 0;
}
