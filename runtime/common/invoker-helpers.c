#include "kbdysch.h"
#include "invoker-utils.h"

DECLARE_BITMASK_KNOB(skip_block_mask, "SKIPPED_BLOCKS")
DECLARE_INT_KNOB_DEF(min_consume, "MIN_CONSUME", 1)
DECLARE_INT_KNOB_DEF(exit_after_max_errors, "MAX_ERRORS", 1000000)

void exit_if_too_many_errors(struct fuzzer_state *state) {
  if (get_num_errors_returned(state) > exit_after_max_errors) {
    fprintf(stderr, "*** Too many errors returned, exiting. ***\n");
    stop_processing(state);
  }
}

void skip_block_if_requested(struct fuzzer_state *state, unsigned block_index) {
  const unsigned max_controlled_blocks = sizeof(skip_block_mask) * 8;
  bool skip_this_block;
  if (block_index >= max_controlled_blocks) {
    fprintf(stderr, "!!! [%03d] Filtering of more than %u blocks is not supported yet.\n",
            block_index, max_controlled_blocks);
    skip_this_block = false;
  } else {
    skip_this_block = skip_block_mask & BIT(block_index);
  }
  if (skip_this_block)
    fprintf(stderr, "!!! [%03u] *** Block will be skipped ***\n", block_index);

  inhibit_syscalls(state, skip_this_block);
}

void align_next_block(struct fuzzer_state *state, int block_index,
                      unsigned decoded_bytes) {
  size_t consume_total = min_consume;
  while (consume_total < decoded_bytes)
    consume_total *= 2;

  size_t bytes_to_skip = consume_total - decoded_bytes;
  res_skip_bytes(state, bytes_to_skip);

  fprintf(stderr,
          "~~~ [%03d] Skipping %zu bytes (%zu bytes consumed in total).\n",
          block_index, bytes_to_skip, consume_total);
}

size_t do_invoke(struct fuzzer_state *state, int block_index) {
  size_t old_offset = res_get_cur_offset(state);
  uint8_t opcode = res_get_u8(state);
  fprintf(stderr, "==> [%03d] Decoding at offset %zu, opcode = 0x%02x...\n",
          block_index, old_offset, (unsigned)opcode);
  invoke_next_op(state, opcode);
  size_t decoded_bytes = res_get_cur_offset(state) - old_offset;
  fprintf(stderr, "<== [%03d] Decoded %zu bytes.\n",
          block_index, decoded_bytes);
  return decoded_bytes;
}

void print_summary_at_exit(struct fuzzer_state *state) {
  size_t processed = res_get_cur_offset(state);
  size_t total = res_get_input_length(state);
  fprintf(stderr, "=== Decoded %zu bytes (%zu bytes left).\n",
          processed, total - processed);
}
