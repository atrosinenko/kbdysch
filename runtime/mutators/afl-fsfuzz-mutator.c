#include "kbdysch/kbdysch.h"
#include "kbdysch/invoker-utils.h"

#include <assert.h>

#define MAX_TEST_CASE_LENGTH (1 << 20)
#define MAX_INPUT_OPS 128

struct mutator_state {
  struct fuzzer_state *f_state;

  const uint8_t *original_data;
  size_t original_length;

  uint8_t output[MAX_TEST_CASE_LENGTH];

  size_t offsets[MAX_INPUT_OPS + 1];
  unsigned num_offsets;
  unsigned current_index, current_delta;
};

void *afl_custom_init(/*afl_state_t*/ void *afl, unsigned int seed) {
  struct mutator_state *state = calloc(1, sizeof(*state));
  const char *args[] = {"", "native"};
  state->f_state = create_state(2, args, NULL);
  kernel_configure_diskless(state->f_state, "." /* current directory */);
  inhibit_syscalls(state->f_state, true);
  disable_logs(true);
  return state;
}

static void compute_offsets(struct mutator_state *state) {
  res_set_input_data(state->f_state, state->original_data, state->original_length);
  if (setjmp(*res_get_stopper_env(state->f_state)) == 0) {
    for (int block_index = 0; block_index < MAX_INPUT_OPS; ++block_index) {
      size_t offset = res_get_cur_offset(state->f_state);
      size_t decoded_bytes = do_invoke(state->f_state, block_index);
      align_next_block(state->f_state, block_index, decoded_bytes);
      // save it now, after full block was parsed successfully
      state->offsets[state->num_offsets++] = offset;
    }
  }
  state->offsets[state->num_offsets] = state->original_length;
}

int afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size) {
  struct mutator_state *state = (struct mutator_state *) data;
  state->original_data = buf;
  state->original_length = buf_size;
  state->num_offsets = 0;
  state->current_index = 0;
  state->current_delta = 0;

  CHECK_THAT(buf_size < MAX_TEST_CASE_LENGTH);
  memcpy(state->output, buf, buf_size);

  compute_offsets(state);
  return state->num_offsets;
}

static unsigned current_trim_offset(struct mutator_state *state) {
  return state->offsets[state->current_index] - state->current_delta;
}

static unsigned current_trim_length(struct mutator_state *state) {
  unsigned original_start = state->offsets[state->current_index];
  unsigned original_end   = state->offsets[state->current_index + 1];
  return original_end - original_start;
}

static void write_original_tail(struct mutator_state *state, unsigned from_index) {
  unsigned trim_offset = current_trim_offset(state);
  unsigned original_tail_offset = state->offsets[from_index];
  assert(original_tail_offset <= state->original_length);
  unsigned tail_length = state->original_length - original_tail_offset;
  memcpy(&state->output[trim_offset],
         &state->original_data[original_tail_offset],
         tail_length);
}

size_t afl_custom_trim(void *data, unsigned char **out_buf) {
  struct mutator_state *state = (struct mutator_state *) data;
  *out_buf = state->output;

  assert(state->current_index < state->num_offsets);
  write_original_tail(state, state->current_index + 1);
  state->current_delta += current_trim_length(state);

  assert(state->current_delta <= state->original_length);
  return state->original_length - state->current_delta;
}

int afl_custom_post_trim(void *data, unsigned char success) {
  struct mutator_state *state = (struct mutator_state *) data;

  if (!success) {
    // *First* restore delta, *then* call write_original_tail()
    state->current_delta -= current_trim_length(state);
    write_original_tail(state, state->current_index);
  }

  state->current_index += 1;
  return state->current_index;
}

void afl_custom_deinit(void *data) {
  free(data);
}
