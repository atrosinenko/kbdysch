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

  assert(MAX_INPUT_LEN == MUTATOR_MAX_TEST_CASE_LENGTH); // statically known
  TRACE(state, "Read %zu bytes of input (max %u).", state->constant_state.length, MAX_INPUT_LEN);
  mutator_init_input(state);
  for (int id = 0; id < state->current_state.file_name_count; ++id)
    mutator_open_resource(RESOURCE_KIND_FILE_NAME, id);
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

void res_align_next_to(struct fuzzer_state *state, size_t alignment) {
  uint64_t old_offset = state->current_state.offset;
  uint64_t new_offset = (old_offset + alignment - 1) / alignment * alignment;
  state->current_state.offset = new_offset;
}

void res_skip_bytes(struct fuzzer_state *state, size_t bytes_to_skip) {
  state->current_state.offset += bytes_to_skip;
}

static uint8_t *get_and_consume(struct fuzzer_state *state, size_t bytes) {
  uint8_t *result = state->constant_state.input_buffer + state->current_state.offset;
  state->current_state.offset += bytes;
  return result;
}

uint64_t res_get_uint(struct fuzzer_state *state, size_t size) {
  uint64_t result = 0;
  assert(size == 1 || size == 2 || size == 4 || size == 8);
  res_align_next_to(state, size);
  if (state->current_state.offset + size > state->constant_state.length)
    stop_processing(state);

  memcpy(&result, get_and_consume(state, size), size);
  return result;
}

void res_copy_bytes(struct fuzzer_state *state, void *ptr, size_t size) {
  if (state->current_state.offset + size > state->constant_state.length)
    stop_processing(state);

  uint8_t *source_ptr = get_and_consume(state, size);
  memcpy(ptr, source_ptr, size);
}

void res_mark_section_start(struct fuzzer_state *state) {
  if (state->current_state.offset >= state->constant_state.length)
    stop_processing(state);
  mutator_write_trim_offset(res_get_cur_offset(state));
}

void res_mark_consumed_reference(struct fuzzer_state *state,
                                 int kind, int id, unsigned id_bytes) {
  unsigned offset = res_get_cur_offset(state) - id_bytes;
  mutator_ref_resource(kind, id, id_bytes, offset);
}

void res_propose_change_here(struct fuzzer_state *state,
                             uint64_t replacement, unsigned size) {
  unsigned offset = res_get_cur_offset(state) - size;
  mutator_propose_change(offset, replacement, size);
}

void res_propose_change_if_different(struct fuzzer_state *state, unsigned offset,
                                     uint64_t replacement, unsigned size) {
  void *current_data = &state->constant_state.input_buffer[offset];
  if (memcmp(&current_data, &replacement, size))
    mutator_propose_change(offset, replacement, size);
}
