#include "kbdysch/base/options.h"
#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"
#include "kbdysch/mutator-interface.h"

DECLARE_BOOL_KNOB(populate_success_rate, "POPULATE_SUCCESS_RATE")
DEBUG_COUNTER(num_tags, "Number of %-prefixed tags processed")

void do_populate_success_rate() {
  // <success_rate>_<num_occurrences>
  const char *labels[] = {
      "always_3",
      "never_0",
      "never_2",
      "frequent_4",
      "rare_3",
      "half_2",
  };
  struct success_rate_info info;
  info = mutator_allocate_success_rate("Dummy success rate", labels, 6);
  mutator_allocate_counters("After dummy success rate", 1);

  // always_3
  mutator_report_success_or_failure(&info, 0, true);
  mutator_report_success_or_failure(&info, 0, true);
  mutator_report_success_or_failure(&info, 0, true);
  // never_0
  // never_2
  mutator_report_success_or_failure(&info, 2, false);
  mutator_report_success_or_failure(&info, 2, false);
  // frequent_4
  mutator_report_success_or_failure(&info, 3, true);
  mutator_report_success_or_failure(&info, 3, true);
  mutator_report_success_or_failure(&info, 3, true);
  mutator_report_success_or_failure(&info, 3, false);
  // rare_3
  mutator_report_success_or_failure(&info, 4, true);
  mutator_report_success_or_failure(&info, 4, false);
  mutator_report_success_or_failure(&info, 4, false);
  // half_2
  mutator_report_success_or_failure(&info, 5, true);
  mutator_report_success_or_failure(&info, 5, false);
}

int from_decimal_digit(char ch) {
  if (ch < '0' || '9' < ch)
    abort();
  return ch - '0';
}

int main(int argc, const char *argv[]) {
  struct fuzzer_state *state = create_state(argc, argv, NULL);
  mutator_init();

  res_load_whole_stdin(state);

  if (populate_success_rate)
    do_populate_success_rate();

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
