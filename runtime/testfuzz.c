#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/mutator-interface.h"
#include "kbdysch/options.h"

DEBUG_COUNTER(num_tags, "Number of %-prefixed tags processed")

int from_decimal_digit(char ch) {
  if (ch < '0' || '9' < ch)
    abort();
  return ch - '0';
}

int main(int argc, const char *argv[]) {
  struct fuzzer_state *state = create_state(argc, argv, NULL);
  mutator_init();

  res_load_whole_stdin(state);

  if (setjmp(*res_get_stopper_env(state)) == 0) {
    for (;;) {
      unsigned kind, id;

      unsigned offset = res_get_cur_offset(state);
      char ch = res_get_u8(state);
      if (ch != '%')
        continue;
      DEBUG_INC(num_tags);

      ch = res_get_u8(state);
      switch (ch) {
      case 'S':
        printf("Section at offset %u.\n", offset);
        mutator_write_trim_offset(offset);
        break;
      case 'N': // [N]ew resource
        kind = from_decimal_digit(res_get_u8(state));
        id   = from_decimal_digit(res_get_u8(state));
        printf("Open resource (kind %u, id = %u).\n", kind, id);
        mutator_open_resource(kind, id);
        break;
      case 'R': // [R]ef resource
        kind = from_decimal_digit(res_get_u8(state));
        id   = from_decimal_digit(res_get_u8(state));
        printf("Reference resource (kind %u, id = %u) at offset %u.\n", kind, id, offset);
        // Use single-byte handle to not 0-terminate input string prematurely
        // %R02
        //    ^
        mutator_ref_resource(kind, id, 1, offset + 3);
        break;
      case 'P': { // [P]ropose change
        // %P<N><M><Bytes> - ask to copy Bytes (of length N) at M bytes larger offset
        // %P24ABCDEFGH -> %P24ABCDABGH
        //     ^^  ^^
        //     --->|
        const unsigned num_skipped_bytes = 4;
        unsigned size  = from_decimal_digit(res_get_u8(state));
        unsigned shift = from_decimal_digit(res_get_u8(state));
        unsigned new_offset = offset + num_skipped_bytes + shift;
        uint64_t payload;
        res_copy_bytes(state, &payload, size);
        mutator_propose_change(new_offset, payload, size);
        break;
      }
      default:
        fprintf(stderr, "Unknown tag: '%c'.\n", ch);
        abort();
      }
    }
  }
}
