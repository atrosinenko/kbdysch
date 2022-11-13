#include "kbdysch/input.h"

#include "kbdysch/common-defs.h"
#include "kbdysch/internal-defs.h"
#include "kbdysch/logging.h"
#include "kbdysch/mutator-interface.h"

#include <assert.h>
#include <string.h>

void res_set_input_data(struct fuzzer_state *state, const uint8_t *data, size_t size) {
  if (size > MAX_INPUT_LEN) {
    WARN(state, "Trying to set %zu input bytes, truncating.", size);
    size = MAX_INPUT_LEN;
  }
  memcpy(state->constant_state.input_buffer, data, size);
  state->constant_state.length = size;
  TRACE(state, "Loaded %zu bytes of input.", size);
}

void res_load_whole_stdin(struct fuzzer_state *state) {
  start_forksrv();
  state->constant_state.length = read(STDIN_FILENO, state->constant_state.input_buffer, MAX_INPUT_LEN);
  if (state->constant_state.length == -1) {
    perror("Cannot read input from stdin");
    abort();
  }
  TRACE(state, "Read %zu bytes of input (max %u).", state->constant_state.length, MAX_INPUT_LEN);
  mutator_init_input(state);
}

void res_rewind_input(struct fuzzer_state *state, size_t offset) {
  state->current_state.offset = offset;
}

size_t res_get_cur_offset(const struct fuzzer_state *state) {
  return state->current_state.offset;
}

ssize_t res_get_input_length(const struct fuzzer_state *state) {
  return state->constant_state.length;
}

const uint8_t *res_get_data_ptr(struct fuzzer_state *state) {
  return state->constant_state.input_buffer;
}
