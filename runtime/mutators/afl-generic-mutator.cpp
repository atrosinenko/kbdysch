#ifdef NDEBUG
#undef NDEBUG
#endif

#include "kbdysch/hashing.h"
#include "kbdysch/mutator-defs.h"
#include "kbdysch/options.h"
#include "afl-interface-decls.h"
#include "helpers.h"
#include "journal.h"
#include "mutations.h"
#include "variables.h"

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

DECLARE_INT_KNOB_DEF(num_best_effort_iterations,
                     "KBDYSCH_MUTATOR_NUM_BEST_EFFORT_ITERATIONS", 100)

using namespace kbdysch::mutator;

struct mutator_state {
  mutator_state();

  // Low-level details
  shm_segment variables_shm;
  shm_segment journal_shm;
  temp_dir journal_dir;

  // Variables area (parsed once per fuzzing session)
  std::vector<variable *> variables;
  bool vars_shm_parsed;

  array_buffer<MUTATOR_MAX_TEST_CASE_LENGTH> input;
  array_buffer<MUTATOR_MAX_TEST_CASE_LENGTH> output;

  journal_data current_journal;
  journal_data additional_journal;

  enum {
    RECORD_LOG_NONE = 0,
    RECORD_LOG_PREPARE_INPUT,
    RECORD_LOG_CAPTURE_LOG,
    RECORD_LOG_CAPTURE_LOG_AS_IS,
  } record_log_next_action;

  bool best_effort_mode;

  std::vector<mutation_strategy *> strategies;
};

mutator_state::mutator_state()
    : variables_shm(MUTATOR_SHM_VARS_ENV_NAME, MUTATOR_SHM_VARS_BYTES, 2 * MUTATOR_SHM_VARS_BYTES),
      journal_shm(MUTATOR_SHM_LOG_ENV_NAME, MUTATOR_SHM_LOG_BYTES, MUTATOR_SHM_LOG_BYTES),
      journal_dir("/tmp/afl-mutator-XXXXXX"),
      current_journal(journal_dir), additional_journal(journal_dir) {
}

static void parse_variables_area(struct mutator_state *state) {
  if (state->vars_shm_parsed)
    return;
  state->vars_shm_parsed = true;

  uint8_t *shm_ptr = state->variables_shm.begin();
  buffer_ref main_area(shm_ptr,
                       MUTATOR_SHM_VARS_BYTES);
  buffer_ref aux_area(shm_ptr + MUTATOR_SHM_VARS_BYTES,
                      MUTATOR_SHM_VARS_BYTES);

  uint8_t *cur_ptr = shm_ptr;
  while (variable::create_from_shm(state->variables, main_area, aux_area, &cur_ptr)) {
  }
}

static void accumulate_important_data(struct mutator_state *state) {
  parse_variables_area(state);
  for (auto variable : state->variables)
    variable->accumulate();
}

static void print_variables(struct mutator_state *state) {
  for (int current_var = 0; current_var < state->variables.size(); ++current_var) {
    state->variables[current_var]->print(stdout, current_var);
  }
}

static size_t read_file(const char *file_name, buffer_ref buffer) {
  int fd = open(file_name, O_RDONLY);
  if (fd < 0)
    FATAL("Cannot file %s\n", file_name);

  int length = read(fd, buffer.bytes(), buffer.size());
  if (length <= 0)
    FATAL("read() returned %d\n", length);
  close(fd);

  return length;
}

static bool save_log_from_shm(struct mutator_state *state,
                              buffer_ref test_case,
                              const char *description) {
  char hash[HASH_CHARS + 1];
  if (test_case.size() == 0) {
    assert(test_case.bytes() == NULL);
    // Don't compare the hash, just save what we got
    memcpy(hash, state->journal_shm.begin(), HASH_CHARS);
    hash[HASH_CHARS] = '\0';
    if (strspn(hash, "0123456789abcdef") != HASH_CHARS) {
      ERR("Unexpected characters in hash\n");
      return false;
    }
  } else {
    kbdysch_compute_hash(hash, test_case.bytes(), test_case.size());
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
  populate_mutation_strategies(state->strategies);

  return state;
}

uint32_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  // Input is loaded by afl_custom_queue_get()
  bool has_log = state->current_journal.load_journal(state->input.as_data());

  state->best_effort_mode = !has_log;
  state->record_log_next_action = has_log ? mutator_state::RECORD_LOG_NONE : mutator_state::RECORD_LOG_PREPARE_INPUT;

  if (state->best_effort_mode) {
    ERR("  %zu bytes, recording log...\n", buf_size);
    return num_best_effort_iterations;
  }

  unsigned num_mutations = 0;
  for (auto *strategy : state->strategies) {
    strategy->reset(state->input.as_data(), state->current_journal);
    num_mutations += strategy->remaining_mutation_count();
  }
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
    if (state->input.size() != buf_size || memcmp(state->input.bytes(), buf, state->input.size()))
      ERR("Unexpected buf and buf_size=%zu\n", buf_size);
    state->record_log_next_action = mutator_state::RECORD_LOG_CAPTURE_LOG;
    *out_buf = buf;
    return buf_size;
  case mutator_state::RECORD_LOG_CAPTURE_LOG:
    ERR("Trying to save log...\n");
    if (!save_log_from_shm(state, state->input.as_data(), "best effort mode"))
      abort();
    accumulate_important_data(state);
    state->current_journal.load_journal(state->input.as_data());
    state->record_log_next_action = mutator_state::RECORD_LOG_NONE;
  case mutator_state::RECORD_LOG_CAPTURE_LOG_AS_IS:
    ERR("Trying to save log as-is...\n");
    if (!save_log_from_shm(state, buffer_ref(), "best effort mode"))
      abort();
    accumulate_important_data(state);
    state->record_log_next_action = mutator_state::RECORD_LOG_NONE;
    break;
  }

  state->output.resize(0);
  mutation_strategy *strategy = nullptr;
  if (state->best_effort_mode) {
    unsigned num_strategies = state->strategies.size();
    unsigned first_index = random() % num_strategies;

    for (unsigned i = 0; i < num_strategies; ++i) {
      auto s = state->strategies[(first_index + i) % num_strategies];
      s->reset(state->input.as_data(), state->current_journal);
      if (s->remaining_mutation_count()) {
        strategy = s;
        break;
      }
    }

    assert(strategy != NULL);
    strategy->randomize(random());
  } else {
    for (auto s : state->strategies) {
      if (!s->remaining_mutation_count())
        continue;
      strategy = s;
      break;
    }
  }
  if (!strategy->needs_add_buf()) {
    strategy->render_next_mutation(state->output,
                                   state->input.as_data(), state->current_journal);
  } else {
    if (!add_buf_size) {
      // add_buf is empty, cannot proceed
      *out_buf = state->input.bytes();
      return state->input.size();
    }

    buffer_ref add_buf_ref(add_buf, add_buf_size);
    if (!state->additional_journal.load_journal(add_buf_ref)) {
      state->record_log_next_action = mutator_state::RECORD_LOG_CAPTURE_LOG_AS_IS;
      *out_buf = add_buf;
      return add_buf_size;
    }
    strategy->render_next_mutation(state->output,
                                   state->input.as_data(), state->current_journal,
                                   add_buf_ref, state->additional_journal);
  }

  *out_buf = state->output.bytes();
  return state->output.size();
}

uint8_t afl_custom_queue_get(void *data, const char *filename) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  parse_variables_area(state);

  state->input.resize(read_file(filename, state->input.as_storage()));

  return 1;
}

uint8_t afl_custom_queue_new_entry(void *data, const char *filename_new_queue,
                                   const char *filename_orig_queue) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  // Save log data for later use

  static array_buffer<MUTATOR_MAX_TEST_CASE_LENGTH> test_case;
  test_case.resize(read_file(filename_new_queue, test_case.as_storage()));

  bool log_saved = save_log_from_shm(state, test_case.as_data(), filename_new_queue);
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

  for (auto s : state->strategies)
    delete s;

  for (auto v : state->variables)
    delete v;

  delete state;

  deinit_error_logging();
}
