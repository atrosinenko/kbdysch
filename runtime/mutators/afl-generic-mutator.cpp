#ifdef NDEBUG
#undef NDEBUG
#endif

#include "kbdysch/hashing.h"
#include "kbdysch/mutator-defs.h"
#include "kbdysch/options.h"
#include "afl-interface-decls.h"
#include "helpers.h"
#include "journal.h"

#include <array>
#include <string>
#include <vector>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

DECLARE_INT_KNOB_DEF(num_splices, "KBDYSCH_MUTATOR_NUM_SPLICES", 4)
DECLARE_INT_KNOB_DEF(num_best_effort_iterations,
                     "KBDYSCH_MUTATOR_NUM_BEST_EFFORT_ITERATIONS", 100)

using namespace kbdysch::mutator;

struct mutator_variable_desc {
  unsigned type;
  mutator_num_elements_t *num_elements;
  unsigned bytes_per_element, max_elements;
  std::string name;
  // Pointer to the original data in SHM
  void *data;
  // Pointer to the storage for data accumulated only for queue entries
  void *important_data;

  bool fill_from_dereferenceable_shm(uint8_t *ptr);
};

struct harness_log {
  std::array<uint8_t, MUTATOR_MAX_LOG_BYTES> raw_log;

  // For convenience, offsets[num_offsets] == input_length
  unsigned offsets[MUTATOR_MAX_OFFSETS + 1];
  unsigned num_offsets;
};

struct mutator_state {
  mutator_state();

  // Low-level details
  shm_segment variables_shm;
  shm_segment journal_shm;
  temp_dir journal_dir;

  // Variables area (parsed once per fuzzing session)
  std::vector<mutator_variable_desc> variables;
  bool vars_shm_parsed;

  uint8_t input[MUTATOR_MAX_TEST_CASE_LENGTH];
  unsigned input_length;

  uint8_t output[MUTATOR_MAX_TEST_CASE_LENGTH];
  unsigned output_length;

  journal_data current_journal;
  journal_data additional_journal;

  enum {
    RECORD_LOG_NONE = 0,
    RECORD_LOG_PREPARE_INPUT,
    RECORD_LOG_CAPTURE_LOG,
    RECORD_LOG_CAPTURE_LOG_AS_IS,
  } record_log_next_action;

  bool best_effort_mode;

  bool skipped_sections[MUTATOR_MAX_OFFSETS];

  unsigned current_mutation;
};

mutator_state::mutator_state()
    : variables_shm(MUTATOR_SHM_VARS_ENV_NAME, MUTATOR_SHM_VARS_BYTES, 2 * MUTATOR_SHM_VARS_BYTES),
      journal_shm(MUTATOR_SHM_LOG_ENV_NAME, MUTATOR_SHM_LOG_BYTES, MUTATOR_SHM_LOG_BYTES),
      journal_dir("/tmp/afl-mutator-XXXXXX"),
      current_journal(journal_dir), additional_journal(journal_dir) {
}

bool mutator_variable_desc::fill_from_dereferenceable_shm(uint8_t *ptr) {
  DECL_WITH_TYPE(struct mutator_var_header, header, ptr);

  type = header->type;
  num_elements = &header->num_elements_real;
  bytes_per_element = (unsigned)header->bytes_per_element;
  max_elements = (unsigned)header->max_num_elements;

  unsigned name_bytes = header->name_bytes; // Prevent sign-extension
  name.assign((char *)&ptr[sizeof(*header)], name_bytes);

  data = &ptr[sizeof(*header) + name_bytes];
  DEBUG("  type = %d, size = %d x %d, name = %s\n",
        type, bytes_per_element, max_elements, name);

  switch (type) {
  case MUTATOR_VAR_COUNTERS:
    if (bytes_per_element != 8) {
      DEBUG("Counter %s: unexpected bytes_per_element = %d.\n",
            name, (int)bytes_per_element);
      return false;
    }
    important_data = calloc(max_elements, bytes_per_element);
    break;
  case MUTATOR_VAR_STRINGS:
    break;
  case MUTATOR_VAR_STOP:
    return false;
  default:
    DEBUG("Unknown var record type: 0x%x\n", (int)type);
    return false;
  }
  return true;
}

static void parse_variables_area(struct mutator_state *state) {
  if (state->vars_shm_parsed)
    return;
  state->vars_shm_parsed = true;

  shm_segment *shm = &state->variables_shm;
  uint8_t *current_ptr = shm->begin();
  for (int current_var = 0; ; ++current_var) {
    DEBUG("Parsing variable #%d...\n", current_var);

    // Check input description is in bounds
    size_t total_bytes = sizeof(struct mutator_var_header);
    if (!shm->in_bounds(current_ptr, total_bytes))
      return;
    DECL_WITH_TYPE(struct mutator_var_header, header, current_ptr);
    total_bytes += (unsigned)header->name_bytes;
    total_bytes += (unsigned)header->bytes_per_element * (unsigned)header->max_num_elements;
    if (!shm->in_bounds(current_ptr, total_bytes))
      return;

    mutator_variable_desc desc;
    if (!desc.fill_from_dereferenceable_shm(current_ptr))
      return;
    state->variables.push_back(desc);
    current_ptr += total_bytes;
  }
}

static void accumulate_important_data(struct mutator_state *state) {
  parse_variables_area(state);
  for (int current_var = 0; current_var < state->variables.size(); ++current_var) {
    struct mutator_variable_desc *v = &state->variables[current_var];
    switch (v->type) {
    case MUTATOR_VAR_COUNTERS: {
      mutator_u64_var_t *accumulated = (mutator_u64_var_t *)v->important_data;
      mutator_u64_var_t *current     = (mutator_u64_var_t *)MUTATOR_SHM_VAR_IN_CURRENT_AREA(v->data);
      for (unsigned i = 0; i < v->max_elements; ++i)
        accumulated[i] += current[i];
      break;
    }
    default:
      break;
    }
  }
}

static void print_scalar_variable(struct mutator_variable_desc *desc, int index) {
  switch (desc->type) {
  case MUTATOR_VAR_COUNTERS: {
    mutator_u64_var_t *counters = (mutator_u64_var_t *)desc->data;
    mutator_u64_var_t *important = (mutator_u64_var_t *)desc->important_data;
    printf("%lu\t%lu", (unsigned long)important[index], (unsigned long)counters[index]);
    break;
  }
  case MUTATOR_VAR_STRINGS: {
    char *strings = (char *)desc->data;
    char *str = &strings[index * desc->bytes_per_element];
    char *str_end = &str[desc->bytes_per_element];
    char tmp = *str_end;
    *str_end = '\0';
    printf("'%s'", str);
    *str_end = tmp;
    break;
  }
  default:
    printf("<UNKNOWN TYPE>");
    break;
  }
}

static void print_variables(struct mutator_state *state) {
  for (int current_var = 0; current_var < state->variables.size(); ++current_var) {
    struct mutator_variable_desc *desc = &state->variables[current_var];
    unsigned num_elements = *desc->num_elements;
    if (num_elements > desc->max_elements) {
      printf("!!! Too many elements: %u, using only the first %u ones.\n",
             num_elements, desc->max_elements);
      num_elements = desc->max_elements;
    }
    if (num_elements == 1) {
      printf("Variable #%u:\t", current_var);
      print_scalar_variable(desc, 0);
      printf("\t - %s\n", desc->name.c_str());
    } else {
      printf("Variable #%u: %s\n", current_var, desc->name.c_str());
      for (unsigned i = 0; i < num_elements; ++i) {
        printf("- [%u] = ", i);
        print_scalar_variable(desc, i);
        printf("\n");
      }
    }
  }
}

// Section 0 is the beginning of file before the first SET_OFFSET
static void render_dropped_section(struct mutator_state *state) {
  const auto &sections = state->current_journal.sections();
  const auto &references = state->current_journal.resource_references();
  const unsigned num_sections = sections.size();
  unsigned output_pos = 0;

  for (const auto &ref : references) {
    if (ref.defining_section >= num_sections ||
        ref.using_section >= num_sections) {
      ERR("Unexpected reference: defines %u / uses %u (total %u)\n",
          ref.defining_section, ref.using_section, num_sections);
      continue;
    }
    if (state->skipped_sections[ref.defining_section])
      state->skipped_sections[ref.using_section] = true;
  }

  auto cur_reference = references.begin();
  for (int section_idx = 0; section_idx < num_sections; ++section_idx) {
    const auto &cur_section = sections[section_idx];

    while (cur_reference != references.end() &&
           cur_reference->using_section < section_idx)
      ++cur_reference;

    if (state->skipped_sections[section_idx])
      continue;

    memcpy(&state->output[output_pos],
           &state->input[cur_section.begin],
           cur_section.size());

    while (cur_reference != references.end() &&
           cur_reference->using_section == section_idx) {
      unsigned kind = cur_reference->reference.kind;
      unsigned id = cur_reference->reference.id;
      unsigned size = cur_reference->reference.id_bytes;

      unsigned offset = cur_reference->reference.offset;
      offset -= cur_section.begin - output_pos;

      uint64_t new_id = 0;
      memcpy(&new_id, &state->output[offset], size);
      for (unsigned i = 0; i < id; ++i) {
        unsigned def_section = state->current_journal.defining_section(kind, i);
        if (def_section < num_sections && state->skipped_sections[def_section])
          --new_id;
      }
      memcpy(&state->output[offset], &new_id, size);

      ++cur_reference;
    }

    output_pos += cur_section.size();
  }

  state->output_length = output_pos;
}

static void render_splice(struct mutator_state *state,
                          int num_prefix_sections,
                          uint8_t *add_buf, size_t add_buf_size) {
  const auto &sections = state->current_journal.sections();
  state->output_length = sections[num_prefix_sections].end;

  memcpy(state->output, state->input, state->output_length);

  if (!add_buf_size)
    return;
  if (!state->additional_journal.load_journal(buffer_ref(add_buf, add_buf_size))) {
    memcpy(state->output, add_buf, add_buf_size);
    state->output_length = add_buf_size;
    state->record_log_next_action = mutator_state::RECORD_LOG_CAPTURE_LOG_AS_IS;
    return;
  }
  const auto &other_sections = state->additional_journal.sections();

  unsigned additional_index = random() & 0xFFFF;
  additional_index %= other_sections.size();
  unsigned suffix_start = other_sections[additional_index].begin;
  if (suffix_start >= add_buf_size)
    return;

  unsigned suffix_length = std::min<unsigned>(
      add_buf_size - suffix_start,
      MUTATOR_MAX_TEST_CASE_LENGTH - state->output_length);

  memcpy(&state->output[state->output_length], &add_buf[suffix_start], suffix_length);
  state->output_length += suffix_length;
}

static size_t read_file(const char *file_name, uint8_t *buffer, size_t max_size) {
  int fd = open(file_name, O_RDONLY);
  if (fd < 0)
    FATAL("Cannot file %s\n", file_name);

  int length = read(fd, buffer, max_size);
  if (length <= 0)
    FATAL("read() returned %d\n", length);
  close(fd);

  return length;
}

static bool save_log_from_shm(struct mutator_state *state,
                              uint8_t *test_case, size_t length,
                              const char *description) {
  char hash[HASH_CHARS + 1];
  if (length == 0) {
    assert(test_case == NULL);
    // Don't compare the hash, just save what we got
    memcpy(hash, state->journal_shm.begin(), HASH_CHARS);
    hash[HASH_CHARS] = '\0';
    if (strspn(hash, "0123456789abcdef") != HASH_CHARS) {
      ERR("Unexpected characters in hash\n");
      return false;
    }
  } else {
    kbdysch_compute_hash(hash, test_case, length);
    hash[HASH_CHARS] = '\0';
    if (memcmp(state->journal_shm.begin(), hash, HASH_CHARS)) {
      char real_hash[HASH_CHARS + 1];
      memcpy(real_hash, state->journal_shm.begin(), HASH_CHARS);
      real_hash[HASH_CHARS] = 0;
      ERR("Hash mismatch:  %s  (%s)\n", hash, description);
      ERR("         Real: [%s]\n", real_hash);
      return false;
    }
  }

  buffer_ref log_contents(&state->journal_shm.begin()[HASH_CHARS], MUTATOR_MAX_LOG_BYTES);
  state->journal_dir.write_file(hash, log_contents);

  return true;
}

void *afl_custom_init(/*afl_state_t*/ void *afl_, unsigned int seed_) {
  DEBUG_TRACE_FUNC;
  (void) afl_;
  (void) seed_;

  init_error_logging();

  mutator_state *state = new mutator_state();

  return state;
}

uint32_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  // Input is loaded by afl_custom_queue_get()
  bool has_log = state->current_journal.load_journal(buffer_ref(state->input, state->input_length));
  state->current_mutation = 0;

  state->best_effort_mode = !has_log;
  state->record_log_next_action = has_log ? mutator_state::RECORD_LOG_NONE : mutator_state::RECORD_LOG_PREPARE_INPUT;

  if (state->best_effort_mode) {
    ERR("  %zu bytes, recording log...\n", buf_size);
    return num_best_effort_iterations;
  }

  const unsigned num_offsets = state->current_journal.sections().size() - 1;
  unsigned num_mutations = 0;
  num_mutations += num_offsets;
  num_mutations += num_offsets * num_splices;
  return num_mutations;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  switch (state->record_log_next_action) {
  case mutator_state::RECORD_LOG_NONE:
    break;
  case mutator_state::RECORD_LOG_PREPARE_INPUT:
    ERR("Requesting log...\n");
    if (state->input_length != buf_size || memcmp(state->input, buf, state->input_length))
      ERR("Unexpected buf and buf_size=%zu\n", buf_size);
    ++state->current_mutation;
    state->record_log_next_action = mutator_state::RECORD_LOG_CAPTURE_LOG;
    *out_buf = buf;
    return buf_size;
  case mutator_state::RECORD_LOG_CAPTURE_LOG:
    ERR("Trying to save log...\n");
    if (!save_log_from_shm(state, state->input, state->input_length, "best effort mode"))
      abort();
    accumulate_important_data(state);
    state->current_journal.load_journal(buffer_ref(state->input, state->input_length));
    state->record_log_next_action = mutator_state::RECORD_LOG_NONE;
  case mutator_state::RECORD_LOG_CAPTURE_LOG_AS_IS:
    ERR("Trying to save log as-is...\n");
    if (!save_log_from_shm(state, NULL, 0, "best effort mode"))
      abort();
    accumulate_important_data(state);
    state->record_log_next_action = mutator_state::RECORD_LOG_NONE;
    break;
  }

  unsigned num_offsets = state->current_journal.sections().size() - 1;

  if (state->best_effort_mode) {
    unsigned index = state->current_mutation % (num_offsets + 1);
    render_splice(state, index, add_buf, add_buf_size);
  } else if (state->current_mutation < num_offsets) {
    memset(state->skipped_sections, 0, sizeof(bool) * MUTATOR_MAX_OFFSETS);
    state->skipped_sections[1 + state->current_mutation] = true;
    render_dropped_section(state);
  } else {
    unsigned index = state->current_mutation - num_offsets;
    index /= num_splices;
    assert(index < num_offsets);
    render_splice(state, 1 + index, add_buf, add_buf_size);
  }
  ++state->current_mutation;
  *out_buf = state->output;
  return state->output_length;
}

uint8_t afl_custom_queue_get(void *data, const char *filename) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  parse_variables_area(state);

  state->input_length = read_file(filename, state->input,
                                  MUTATOR_MAX_TEST_CASE_LENGTH);

  return 1;
}

uint8_t afl_custom_queue_new_entry(void *data, const char *filename_new_queue,
                                   const char *filename_orig_queue) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  // Save log data for later use

  static uint8_t test_case[MUTATOR_MAX_TEST_CASE_LENGTH];
  int length = read_file(filename_new_queue, test_case,
                         MUTATOR_MAX_TEST_CASE_LENGTH);

  bool log_saved = save_log_from_shm(state, test_case, length, filename_new_queue);
  if (!log_saved && !strstr(filename_new_queue, ",orig:"))
    FATAL("Unexpected hash: %s\n", filename_new_queue);
  // Do not initialize too early
  if (log_saved)
    accumulate_important_data(state);

  return 0;
}

void afl_custom_deinit(void *data) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  parse_variables_area(state);
  print_variables(state);

  delete state;

  deinit_error_logging();
}
