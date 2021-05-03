#include "kbdysch.h"
#include "invoker-utils.h"

void align_next_block(struct fuzzer_state *state, int block_index,
                      unsigned decoded_bytes) {
  size_t consume_total = 1;
  while (consume_total < decoded_bytes)
    consume_total *= 2;

  size_t bytes_to_skip = consume_total - decoded_bytes;
  res_skip_bytes(state, bytes_to_skip);

  fprintf(stderr,
          "~~~ [%03d] Skipping %zu bytes (%zu bytes consumed in total).\n",
          block_index, bytes_to_skip, consume_total);
}

size_t do_invoke(struct fuzzer_state *state, int block_index) {
  uint8_t opcode = res_get_u8(state);
  size_t old_offset = res_get_cur_offset(state);
  fprintf(stderr, "==> [%03d] Decoding at offset %zu, opcode = %u...\n",
          block_index, old_offset, (unsigned)opcode);
  invoke_next_op(state, opcode);
  size_t decoded_bytes = res_get_cur_offset(state) - old_offset;
  fprintf(stderr, "<== [%03d] Decoded %zu bytes.\n",
          block_index, decoded_bytes);
  return decoded_bytes;
}
