#include "kbdysch.h"
#include "invoker-utils.h"

static const int MAX_INPUT_OPS = 25;

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
    for (int i = 2; i < argc; ++i) {
      kernel_setup_disk(state, argv[i], argv[i]);
    }
    kernel_boot(state, argv[1]);
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
