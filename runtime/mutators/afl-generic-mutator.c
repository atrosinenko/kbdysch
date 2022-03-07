#include "mutator-defs.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#define FATAL(fmt, ...) { fprintf(stderr, (fmt), __VA_ARGS__); abort(); }
#define DEBUG(fmt, ...) // fprintf(stderr, "%s: " fmt, __func__, __VA_ARGS__)

#define BUFFER_INFO_REQUEST_PENDING (-2u)
#define BUFFER_INFO_REQUESTED       (-1u)

struct mutator_state {
  int shm_id;
  uint32_t *shm_words;

  uint8_t input[MUTATOR_MAX_TEST_CASE_LENGTH];
  uint8_t output[MUTATOR_MAX_TEST_CASE_LENGTH];
  unsigned original_length;
  unsigned accepted_length;
  unsigned proposed_length;

  unsigned offsets[MUTATOR_MAX_TRIM_OFFSETS + 1];
  unsigned num_offsets;

  unsigned current_index;
};

static void parse_offsets(struct mutator_state *state);

void *afl_custom_init(/*afl_state_t*/ void *afl_, unsigned int seed_) {
  (void) afl_;
  (void) seed_;

  struct mutator_state *state = calloc(1, sizeof(*state));
  size_t shm_size = MUTATOR_MAX_SHM_WORDS * sizeof(state->shm_words[0]);
  state->shm_id = shmget(IPC_PRIVATE, shm_size, 0600);
  state->shm_words = shmat(state->shm_id, NULL, 0);

  char buf[32];
  sprintf(buf, "%d", state->shm_id);
  setenv(MUTATOR_ENV_NAME, buf, 1);
  return state;
}

int afl_custom_init_trim(void *data, unsigned char *buf, size_t buf_size) {
  struct mutator_state *state = (struct mutator_state *) data;

  if (buf_size > MUTATOR_MAX_TEST_CASE_LENGTH) {
    buf_size = MUTATOR_MAX_TEST_CASE_LENGTH;
    fprintf(stderr, __FILE__ ": warning: test case size is larger than %d bytes.",
            MUTATOR_MAX_TEST_CASE_LENGTH);
  }

  memcpy(state->input, buf, buf_size);
  memcpy(state->output, buf, buf_size);
  state->original_length = buf_size;
  state->accepted_length = buf_size;

  state->num_offsets = BUFFER_INFO_REQUEST_PENDING;
  state->current_index = 0;

  return 1;
}

size_t afl_custom_trim(void *data, unsigned char **out_buf) {
  struct mutator_state *state = (struct mutator_state *) data;
  *out_buf = state->output;

  DEBUG("cur_index = %u, num_offsets = %u, %u/%u\n",
        state->current_index, state->num_offsets,
        state->accepted_length, state->original_length);

  if (state->num_offsets == BUFFER_INFO_REQUEST_PENDING) {
    state->num_offsets = BUFFER_INFO_REQUESTED;
    state->shm_words[0] = MUTATOR_OP_STOP;
    return state->accepted_length;
  }
  // SHM buffer contents are parsed by post-trim
  assert(state->num_offsets != BUFFER_INFO_REQUESTED);

  assert(state->current_index < state->num_offsets);

  unsigned trimmed_bytes = state->original_length - state->accepted_length;
  uint32_t accepted_start = state->offsets[state->current_index]     - trimmed_bytes;
  uint32_t accepted_end   = state->offsets[state->current_index + 1] - trimmed_bytes;
  DEBUG("cutting %u-%u (%u bytes)\n",
        accepted_start, accepted_end, accepted_end - accepted_start);

  memcpy(state->output, state->input, accepted_start);
  memcpy(&state->output[accepted_start],
         &state->input[accepted_end],
         state->accepted_length - accepted_end);

  state->proposed_length = state->accepted_length - (accepted_end - accepted_start);

  return state->proposed_length;
}

int afl_custom_post_trim(void *data, unsigned char success) {
  struct mutator_state *state = (struct mutator_state *) data;
  DEBUG("cur_index = %u, num_offsets = %u, success = %d\n",
        state->current_index, state->num_offsets, (int) success);

  assert(state->num_offsets != BUFFER_INFO_REQUEST_PENDING);
  if (state->num_offsets == BUFFER_INFO_REQUESTED) {
    parse_offsets(state);
    return 0;
  }

  if (success) {
    memcpy(state->input, state->output, state->proposed_length);
    state->accepted_length = state->proposed_length;
  }

  state->current_index += 1;
  return !(state->current_index < state->num_offsets);
}

void afl_custom_deinit(void *data) {
  struct mutator_state *state = (struct mutator_state *) data;
  shmdt(state->shm_words);
  shmctl(state->shm_id, IPC_RMID, NULL);
  free(data);
}

static void parse_offsets(struct mutator_state *state) {
  state->num_offsets = 0;
  int current_word = 0;
  for (;;) {
    if (current_word + 2 > MUTATOR_MAX_SHM_WORDS)
      break;

    unsigned opcode = state->shm_words[current_word++];
    switch (opcode) {
    case MUTATOR_OP_STOP: {
      DEBUG("parsed %u SHM words\n", current_word);
      state->offsets[state->num_offsets] = state->original_length;
      return;
    }
    case MUTATOR_OP_TRIM_OFFSET: {
      unsigned offset = state->shm_words[current_word++];
      DEBUG("parsed trim offset #%u: %u\n", state->num_offsets, offset);
      if (offset < state->original_length)
        state->offsets[state->num_offsets++] = offset;
      break;
    }
    default:
      FATAL("Unknown opcode %u at buffer offset %d\n", opcode, current_word);
    }
  }
}
