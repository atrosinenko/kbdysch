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
#define DECL_WITH_TYPE(type, new_name, ptr) \
  type *new_name = (type *)(ptr)

#define DATA_ARG void *data
#define DECLARE_STATE_VAR \
  DECL_WITH_TYPE(struct mutator_state, state, data)

#define DEBUG_TRACE_FUNC // fprintf(stderr, "%s: called\n", __func__)
#define DEBUG(fmt, ...)  // fprintf(stderr, "%s: " fmt, __func__, __VA_ARGS__)

#define BUFFER_INFO_REQUEST_PENDING (-2u)
#define BUFFER_INFO_REQUESTED       (-1u)

struct fixed_record_desc {
  int type;
  mutator_shm_word *num_elements;
  int size_of_element, max_elements;
  char *name;
  void *data;
};

struct mutator_state {
  // Low-level details
  int shm_id;
  void *shm_segment;

  // Current parsing state
  bool fixed_section_parsed;

  // Fixed-structure section (parsed once per fuzzing session)
  int num_fixed_records;
  struct fixed_record_desc fixed_records[MUTATOR_MAX_FIXED_RECORDS];
  void *shm_bytecode_start;

  // Not SHM-related variables
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

static void init_shm(struct mutator_state *state) {
  char buf[32];
  // Allocate SHM segment
  state->shm_id = shmget(IPC_PRIVATE, MUTATOR_SHM_SIZE, 0600);
  state->shm_segment = shmat(state->shm_id, NULL, 0);
  // Make SHM discoverable by harness
  sprintf(buf, "%d", state->shm_id);
  setenv(MUTATOR_ENV_NAME, buf, 1);
}

static void drop_shm(struct mutator_state *state) {
  shmdt(state->shm_segment);
  shmctl(state->shm_id, IPC_RMID, NULL);
}

static bool check_in_bounds(struct mutator_state *state, void *ptr, size_t size) {
  uintptr_t shm_start = (uintptr_t)state->shm_segment;
  uintptr_t start = (uintptr_t)ptr;

  if (start < shm_start) {
    DEBUG("Pointer %p outside of SHM segment (starting at %p).\n",
          ptr, state->shm_segment);
    return false;
  }
  size_t offset_in_shm = start - shm_start;
  if (offset_in_shm > MUTATOR_SHM_SIZE ||
      size > MUTATOR_SHM_SIZE ||
      offset_in_shm + size > MUTATOR_SHM_SIZE) {
    DEBUG("Pointer %p at invalid offset 0x%zx in SHM segment (size 0x%zx).\n",
          ptr, offset_in_shm, MUTATOR_SHM_SIZE);
    return false;
  }
  return true;
}

static bool parse_fixed_section(struct mutator_state *state) {
  uint8_t *current_ptr = state->shm_segment;
  for (int current_record = 0; ; ++current_record) {
    DEBUG("Parsing fixed record #%d...\n", current_record);
    // Find output description structure
    if (current_record >= MUTATOR_MAX_FIXED_RECORDS) {
      DEBUG("Too many records (max %d supported).\n",
            MUTATOR_MAX_FIXED_RECORDS);
      return false;
    }
    struct fixed_record_desc *desc = &state->fixed_records[current_record];

    // Check input description is in bounds
    size_t record_size = sizeof(struct mutator_fixed_record_header);
    if (!check_in_bounds(state, current_ptr, record_size))
      return false;
    DECL_WITH_TYPE(struct mutator_fixed_record_header, header, current_ptr);
    record_size += sizeof(mutator_shm_word) *
        (header->name_words + header->element_words * header->max_num_elements);
    if (!check_in_bounds(state, current_ptr, record_size))
      return false;

    // Parse input description
    desc->type = header->type;
    desc->num_elements = &header->num_elements_mut;
    desc->size_of_element = header->element_words * sizeof(mutator_shm_word);
    desc->max_elements = header->max_num_elements;
    size_t name_size = header->name_words * sizeof(mutator_shm_word);
    desc->name = malloc(name_size + 1);
    memcpy(desc->name, current_ptr + sizeof(*header), name_size);
    desc->name[name_size] = '\0';
    desc->data = current_ptr + sizeof(*header) + name_size;
    DEBUG("  type = %d, size = %d x %d, name = %s\n",
          desc->type, desc->size_of_element, desc->max_elements, desc->name);

    current_ptr += record_size;
    switch (header->type) {
    case MUTATOR_FIXED_RECORD_COUNTERS:
      if (header->element_words != 2) {
        DEBUG("Counter %s: unexpected element_words = %d.\n",
              desc->name, (int)header->element_words);
        return false;
      }
      break;
    case MUTATOR_FIXED_RECORD_STRINGS:
      break;
    case MUTATOR_FIXED_RECORD_STOP:
      if (*(mutator_shm_word *)current_ptr != MUTATOR_END_OF_FIXED_SECTION_MARK) {
        DEBUG("End of fixed-structure section marker: expected 0x%x, got 0x%x.\n",
              MUTATOR_END_OF_FIXED_SECTION_MARK, *(mutator_shm_word *)current_ptr);
        return false;
      }
      current_ptr += sizeof(mutator_shm_word);
      state->num_fixed_records = current_record;
      state->shm_bytecode_start = current_ptr;
      state->fixed_section_parsed = true;
      return true;
    default:
      DEBUG("Unknown fixed record type: 0x%x\n", (int)header->type);
      return false;
    }
  }
}

static void print_scalar_variable(struct fixed_record_desc *desc, int index) {
  switch (desc->type) {
  case MUTATOR_FIXED_RECORD_COUNTERS: {
    uint64_t *counters = desc->data;
    printf("%lu", (unsigned long)counters[index]);
    break;
  }
  case MUTATOR_FIXED_RECORD_STRINGS: {
    char *strings = desc->data;
    char *str = &strings[index * desc->size_of_element];
    str[desc->size_of_element - 1] = '\0';
    printf("'%s'", str);
    break;
  }
  default:
    printf("<UNKNOWN TYPE>");
    break;
  }
}

static void print_variables(struct mutator_state *state) {
  for (int record_index = 0; record_index < state->num_fixed_records; ++record_index) {
    struct fixed_record_desc *desc = &state->fixed_records[record_index];
    unsigned num_elements = *desc->num_elements;
    if (num_elements > desc->max_elements) {
      printf("!!! Too many elements: %u, using only the first %d ones.\n",
             num_elements, desc->max_elements);
      num_elements = desc->max_elements;
    }
    if (num_elements == 1) {
      printf("Variable #%u:\t", record_index);
      print_scalar_variable(desc, 0);
      printf("\t - %s\n", desc->name);
    } else {
      printf("Variable #%u: %s\n", record_index, desc->name);
      for (unsigned i = 0; i < num_elements; ++i) {
        printf("- [%u] = ", i);
        print_scalar_variable(desc, i);
        printf("\n");
      }
    }
  }
}

void *afl_custom_init(/*afl_state_t*/ void *afl_, unsigned int seed_) {
  DEBUG_TRACE_FUNC;
  (void) afl_;
  (void) seed_;

  struct mutator_state *state = calloc(1, sizeof(*state));
  init_shm(state);

  return state;
}

int afl_custom_init_trim(DATA_ARG, unsigned char *buf, size_t buf_size) {
  DEBUG_TRACE_FUNC;
  DECLARE_STATE_VAR;

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

size_t afl_custom_trim(DATA_ARG, unsigned char **out_buf) {
  DEBUG_TRACE_FUNC;
  DECLARE_STATE_VAR;
  *out_buf = state->output;

  if (!state->fixed_section_parsed) {
    if (!parse_fixed_section(state)) {
      fprintf(stderr, "Cannot parse fixed section");
      abort();
    }
  }

  DEBUG("cur_index = %u, num_offsets = %u, %u/%u\n",
        state->current_index, state->num_offsets,
        state->accepted_length, state->original_length);

  if (state->num_offsets == BUFFER_INFO_REQUEST_PENDING) {
    state->num_offsets = BUFFER_INFO_REQUESTED;
    *(mutator_shm_word *)state->shm_bytecode_start = MUTATOR_OPCODE_STOP;
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

int afl_custom_post_trim(DATA_ARG, unsigned char success) {
  DEBUG_TRACE_FUNC;
  DECLARE_STATE_VAR;
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

void afl_custom_deinit(DATA_ARG) {
  DEBUG_TRACE_FUNC;
  DECLARE_STATE_VAR;

  print_variables(state);

  for (int i = 0; i < state->num_fixed_records; ++i) {
    free(state->fixed_records[i].name);
  }
  drop_shm(state);
  free(data);
}

static void parse_offsets(struct mutator_state *state) {
  DEBUG_TRACE_FUNC;
  state->num_offsets = 0;
  int current_word = 0;
  DECL_WITH_TYPE(mutator_shm_word, current_ptr, state->shm_bytecode_start);
  for (;;) {
    if (state->num_offsets >= MUTATOR_MAX_TRIM_OFFSETS)
      break;
    if (!check_in_bounds(state, current_ptr, 2 * sizeof(mutator_shm_word)))
      break;

    unsigned opcode = *(current_ptr++);
    switch (opcode) {
    case MUTATOR_OPCODE_STOP: {
      DEBUG("parsed %u SHM words\n", current_word);
      state->offsets[state->num_offsets] = state->original_length;
      return;
    }
    case MUTATOR_OPCODE_SET_OFFSET: {
      unsigned offset = *(current_ptr++);
      DEBUG("parsed trim offset #%u: %u\n", state->num_offsets, offset);
      if (offset < state->original_length)
        state->offsets[state->num_offsets++] = offset;
      break;
    }
    default:
      FATAL("Unknown opcode %u at buffer offset %d\n", opcode, current_word);
    }
  }
  state->offsets[state->num_offsets] = state->original_length;
}
