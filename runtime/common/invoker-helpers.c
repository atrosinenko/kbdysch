#include "kbdysch/base/options.h"
#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"

DECLARE_BITMASK_KNOB(skip_block_mask, "SKIPPED_BLOCKS")
DECLARE_INT_KNOB_DEF(min_consume, "MIN_CONSUME", 1)
DECLARE_INT_KNOB_DEF(exit_after_max_errors, "MAX_ERRORS", 1000000)
DECLARE_BOOL_KNOB(round_block_to_pow2, "ROUND_BLOCK_TO_POW2")

void exit_if_too_many_errors(struct fuzzer_state *state) {
  if (get_num_errors_returned(state) > exit_after_max_errors) {
    WARN(state, "*** Too many errors returned, exiting. ***");
    stop_processing(state);
  }
}

void skip_block_if_requested(struct fuzzer_state *state, unsigned block_index) {
  const unsigned max_controlled_blocks = sizeof(skip_block_mask) * 8;
  bool skip_this_block;
  if (block_index >= max_controlled_blocks) {
    WARN(state, "!!! [%03d] Filtering of more than %u blocks is not supported yet.",
         block_index, max_controlled_blocks);
    skip_this_block = false;
  } else {
    skip_this_block = skip_block_mask & BIT(block_index);
  }
  if (skip_this_block)
    TRACE(state, "!!! [%03u] *** Block will be skipped ***", block_index);

  inhibit_syscalls(state, skip_this_block);
}

void align_next_block(struct fuzzer_state *state, int block_index,
                      unsigned decoded_bytes) {
  if (!round_block_to_pow2)
    return;

  size_t consume_total = min_consume;
  while (consume_total < decoded_bytes)
    consume_total *= 2;

  size_t bytes_to_skip = consume_total - decoded_bytes;
  res_skip_bytes(state, bytes_to_skip);

  TRACE(state, "~~~ [%03d] Skipping %zu bytes (%zu bytes consumed in total).",
        block_index, bytes_to_skip, consume_total);
}

size_t do_invoke(struct fuzzer_state *state, int block_index,
                 invoker_entry_t invoker_entry) {
  size_t old_offset = res_get_cur_offset(state);
  uint8_t opcode = res_get_u8(state);
  TRACE(state, "==> [%03d] Decoding at offset %zu, opcode = 0x%02x...",
        block_index, old_offset, (unsigned)opcode);
  invoker_entry(state, opcode);
  size_t decoded_bytes = res_get_cur_offset(state) - old_offset;
  TRACE(state, "<== [%03d] Decoded %zu bytes.", block_index, decoded_bytes);
  return decoded_bytes;
}

void print_summary_at_exit(struct fuzzer_state *state) {
  size_t processed = res_get_cur_offset(state);
  size_t total = res_get_input_length(state);
  TRACE(state, "=== Decoded %zu bytes (%zu bytes left).",
        processed, total - processed);
}
