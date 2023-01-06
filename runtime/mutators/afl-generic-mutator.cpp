#ifdef NDEBUG
#undef NDEBUG
#endif

#include "kbdysch/mutator-defs.h"
#include "kbdysch/options.h"
#include "kbdysch/hashing.h"
#include "afl-interface-decls.h"

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

#include <sys/ipc.h>
#include <sys/shm.h>

DECLARE_BOOL_KNOB(debug_logging, "KBDYSCH_MUTATOR_DEBUG")
DECLARE_INT_KNOB_DEF(num_splices, "KBDYSCH_MUTATOR_NUM_SPLICES", 4)
DECLARE_INT_KNOB_DEF(num_best_effort_iterations,
                     "KBDYSCH_MUTATOR_NUM_BEST_EFFORT_ITERATIONS", 100)

#define FATAL(fmt, ...) { fprintf(stderr, "MUTATOR: " fmt, __VA_ARGS__); abort(); }
#define ERR(...) { if (error_log) fprintf(error_log, __VA_ARGS__); }

#define DECL_WITH_TYPE(type, new_name, ptr) \
  type *new_name = (type *)(ptr)

#define DEBUG_TRACE_FUNC // fprintf(stderr, "MUTATOR: %s: called\n", __func__)
#define DEBUG(fmt, ...)  // fprintf(stderr, "MUTATOR: %s: " fmt, __func__, __VA_ARGS__)

static FILE *error_log;

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

class mutator_shm {
public:
  mutator_shm(const char *env_var_name,
              size_t allocatable_bytes, size_t total_bytes);

  uint8_t *begin() { return shm_segment; }

  bool in_bounds(uint8_t *ptr, size_t length) const;

  ~mutator_shm();

private:
  int shm_id;
  uint8_t *shm_segment;
  size_t allocatable_bytes;
};

class mutator_temp_dir {
public:
  mutator_temp_dir(const char *name);

  int fd() const { return dir_fd; }

  ~mutator_temp_dir();

private:
  static const size_t MAX_DIR_NAME = 128;
  char dir_name[MAX_DIR_NAME];
  int dir_fd;
};

struct harness_log {
  uint8_t raw_log[MUTATOR_MAX_LOG_BYTES];

  // For convenience, offsets[num_offsets] == input_length
  unsigned offsets[MUTATOR_MAX_OFFSETS + 1];
  unsigned num_offsets;
};

struct mutator_state {
  // Low-level details
  mutator_shm *variables_shm;
  mutator_shm *log_shm;
  mutator_temp_dir *log_dir;

  // Variables area (parsed once per fuzzing session)
  std::vector<mutator_variable_desc> variables;
  bool vars_shm_parsed;

  uint8_t input[MUTATOR_MAX_TEST_CASE_LENGTH];
  unsigned input_length;

  uint8_t output[MUTATOR_MAX_TEST_CASE_LENGTH];
  unsigned output_length;

  struct harness_log current_log;
  struct harness_log additional_log;

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

static void init_error_logging(void) {
  if (!debug_logging)
    return;

  char log_name[128];
  sprintf(log_name, "/tmp/kbdysch-mutator-%d.log", getpid());
  error_log = fopen(log_name, "w");
  setvbuf(error_log, NULL, _IONBF, 0);
}

static bool in_bounds(const void *mem_area, size_t mem_size,
                      const void *ptr, size_t requested_size) {
  uintptr_t mem_start = (uintptr_t)mem_area;
  uintptr_t ptr_start = (uintptr_t)ptr;

  if ((uintptr_t)ptr < (uintptr_t)mem_area) {
    ERR("Pointer %p outside of memory area starting at %p.\n",
        ptr, mem_area);
    return false;
  }
  size_t offset_in_mem_area = (uintptr_t)ptr - (uintptr_t)mem_area;
  if (offset_in_mem_area > mem_size ||
      requested_size > mem_size ||
      offset_in_mem_area + requested_size > mem_size) {
    ERR("Pointer %p at invalid offset 0x%zx in memory area of size 0x%zx.\n",
        ptr, offset_in_mem_area, mem_size);
    return false;
  }
  return true;
}

mutator_shm::mutator_shm(const char *env_var_name,
                         size_t allocatable_bytes, size_t total_bytes)
    : allocatable_bytes(allocatable_bytes) {
  char buf[32];
  // Allocate SHM segment
  shm_id = shmget(IPC_PRIVATE, total_bytes, 0600);
  shm_segment = (uint8_t *)shmat(shm_id, NULL, 0);
  // Make SHM discoverable by harness
  sprintf(buf, "%d", shm_id);
  setenv(env_var_name, buf, 1);
}

bool mutator_shm::in_bounds(uint8_t *ptr, size_t length) const {
  return ::in_bounds(shm_segment, allocatable_bytes,
                     ptr, length);
}

mutator_shm::~mutator_shm() {
  shmdt(shm_segment);
  shmctl(shm_id, IPC_RMID, NULL);
}

mutator_temp_dir::mutator_temp_dir(const char *name) {
  strncpy(dir_name, name, MAX_DIR_NAME);
  dir_name[MAX_DIR_NAME - 1] = 0;
  mkdtemp(dir_name);

  dir_fd = open(dir_name, O_RDONLY);
  assert(dir_fd >= 0);
}

mutator_temp_dir::~mutator_temp_dir() {
  close(dir_fd);
  // TODO remove directory
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

  mutator_shm *shm = state->variables_shm;
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

#define ITERATE_LOG_HEADERS(log_data, loop_body) \
  for (int header_offset = 0; header_offset < MUTATOR_MAX_LOG_BYTES; ) { \
    const uint8_t *ptr = &(log_data)[header_offset];                     \
    size_t total_bytes = sizeof(struct mutator_log_record_header);       \
    total_bytes += 16; /* FIXME payload size */                          \
    if (!in_bounds((log_data), MUTATOR_MAX_LOG_BYTES, ptr, total_bytes)) \
      ERR("Error parsing log, offset %d\n", header_offset);              \
    DECL_WITH_TYPE(struct mutator_log_record_header, header, ptr);       \
    const void *payload = &ptr[sizeof(*header)];                         \
    loop_body;                                                           \
    if (header->type == MUTATOR_LOG_STOP)                                \
      break;                                                             \
    header_offset += header->size;                                       \
  }

static bool load_log(struct mutator_state *state,
                     struct harness_log *log,
                     const uint8_t *buf, size_t buf_length) {
  char hash[HASH_CHARS + 1];
  kbdysch_compute_hash(hash, buf, buf_length);
  hash[HASH_CHARS] = '\0';

  int log_fd = openat(state->log_dir->fd(), hash, O_RDONLY);
  if (log_fd < 0) {
    ERR("Cannot open log for hash %s\n", hash);
    memset(log, 0, sizeof(*log));
    return false;
  }

  int length = read(log_fd, log->raw_log, MUTATOR_MAX_LOG_BYTES);
  if (length < 0)
    FATAL("Cannot read log: %s", strerror(errno));
  if (length < MUTATOR_MAX_LOG_BYTES) {
    DEBUG("Read only %d bytes of log.", length);
    memset(&log->raw_log[length], 0, MUTATOR_MAX_LOG_BYTES - length);
  }
  close(log_fd);

  // Parse offsets
  log->num_offsets = 0;
  ITERATE_LOG_HEADERS(log->raw_log, {
    if (header->type == MUTATOR_LOG_SET_OFFSET) {
      DECL_WITH_TYPE(struct mutator_log_set_offset, set_offset, payload);
      if (set_offset->offset >= state->input_length)
        break;
      log->offsets[log->num_offsets++] = set_offset->offset;
    }
  });
  if (log->num_offsets && log->offsets[log->num_offsets - 1] >= buf_length) {
    ERR("Out of bounds offset: %u at index %u.\n",
        log->offsets[log->num_offsets - 1], log->num_offsets - 1);
  }
  log->offsets[log->num_offsets] = buf_length;

  return true;
}

// Section 0 is the beginning of file before the first SET_OFFSET
static void render_dropped_section(struct mutator_state *state) {
  unsigned input_pos = 0;
  unsigned output_pos = 0;

  uint16_t resources[MUTATOR_MAX_RESOURCE_KINDS][MUTATOR_MAX_RESOURCE_IDS];
  memset(&resources, -1, sizeof(resources));

  int current_section = 0;
  unsigned saved_input_pos = 0;
  // For rolling back if non-existing resource is referenced
  unsigned saved_output_pos = 0;

  // Copy header
  memcpy(state->output, state->input, state->current_log.offsets[0]);
  saved_input_pos  = input_pos  = state->current_log.offsets[0];
  saved_output_pos = output_pos = state->current_log.offsets[0];

  ITERATE_LOG_HEADERS(state->current_log.raw_log, {
    switch (header->type) {
    case MUTATOR_LOG_STOP:
      break;
    case MUTATOR_LOG_SET_OFFSET: {
      ++current_section;
      saved_input_pos = input_pos;
      saved_output_pos = output_pos;

      // offset n <-> section (n+1)
      unsigned input_pos_next = state->current_log.offsets[current_section];
      if (input_pos_next < input_pos)
        break;

      // copy the next portion of input, so it can be patched as needed
      if (!state->skipped_sections[current_section]) {
        unsigned length = input_pos_next - input_pos;
        memcpy(&state->output[output_pos],
               &state->input[input_pos],
               length);
        output_pos += length;
      }

      input_pos = input_pos_next;
      break;
    }
    case MUTATOR_LOG_NEW_RES: {
      DECL_WITH_TYPE(struct mutator_log_new_resource, new_res, payload);
      unsigned kind = new_res->kind;
      unsigned id = new_res->id;
      if (kind >= MUTATOR_MAX_RESOURCE_KINDS || id >= MUTATOR_MAX_RESOURCE_IDS) {
        ERR("Section %u, new resource: invalid kind=%u, id=%u\n", current_section, kind, id);
        break;
      }
      resources[new_res->kind][new_res->id] = current_section;
      break;
    }
    case MUTATOR_LOG_REF_RES: {
      DECL_WITH_TYPE(struct mutator_log_ref_resource, ref_res, payload);
      unsigned kind = ref_res->kind;
      unsigned id = ref_res->id;
      if (kind >= MUTATOR_MAX_RESOURCE_KINDS || id >= MUTATOR_MAX_RESOURCE_IDS) {
        ERR("Section %u, referenced resource: invalid kind=%u, id=%u\n", current_section, kind, id);
        break;
      }
      unsigned defining_section = resources[kind][id];
      if (defining_section > current_section) {
        ERR("Section %u, referenced resource (%u, %u) defined by section %u\n",
            current_section, kind, id, defining_section);
        break;
      }
      if (state->skipped_sections[defining_section]) {
        state->skipped_sections[current_section] = true;
        output_pos = saved_output_pos;
        break;
      }

      if (state->skipped_sections[current_section])
        break;

      unsigned output_offset = ref_res->offset - saved_input_pos + saved_output_pos;
      unsigned size = ref_res->id_bytes;
      if (output_offset + size > output_pos || size > 8) {
        ERR("Invalid resource reference: output_offset = %u, size = %u\n",
            output_offset, size);
        break;
      }

      uint64_t new_id = 0;
      memcpy(&new_id, &state->output[output_offset], size);
      for (unsigned i = 0; i < id; ++i)
        if (state->skipped_sections[resources[kind][i]])
          new_id -= 1;
      memcpy(&state->output[output_offset], &new_id, size);
      break;
    }
    default:
      FATAL("Unknown type of log record: %u\n", (unsigned)header->type);
    }
  });
  state->output_length = output_pos;
}

static void render_splice(struct mutator_state *state,
                          int num_prefix_sections,
                          uint8_t *add_buf, size_t add_buf_size) {
  state->output_length = state->current_log.offsets[num_prefix_sections];

  memcpy(state->output, state->input, state->output_length);

  if (!add_buf_size)
    return;
  if (!load_log(state, &state->additional_log, add_buf, add_buf_size)) {
    memcpy(state->output, add_buf, add_buf_size);
    state->output_length = add_buf_size;
    state->record_log_next_action = mutator_state::RECORD_LOG_CAPTURE_LOG_AS_IS;
    return;
  }
  if (!state->additional_log.num_offsets)
    return;

  unsigned additional_index = random() & 0xFFFF;
  additional_index %= state->additional_log.num_offsets;
  unsigned suffix_start = state->additional_log.offsets[additional_index];
  if (suffix_start >= add_buf_size)
    return;

  unsigned suffix_length = add_buf_size - suffix_start;
  if (state->output_length + suffix_length > MUTATOR_MAX_TEST_CASE_LENGTH)
    suffix_length = MUTATOR_MAX_TEST_CASE_LENGTH - state->output_length;

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
    memcpy(hash, state->log_shm->begin(), HASH_CHARS);
    hash[HASH_CHARS] = '\0';
    if (strspn(hash, "0123456789abcdef") != HASH_CHARS) {
      ERR("Unexpected characters in hash\n");
      return false;
    }
  } else {
    kbdysch_compute_hash(hash, test_case, length);
    hash[HASH_CHARS] = '\0';
    if (memcmp(state->log_shm->begin(), hash, HASH_CHARS)) {
      char real_hash[HASH_CHARS + 1];
      memcpy(real_hash, state->log_shm->begin(), HASH_CHARS);
      real_hash[HASH_CHARS] = 0;
      ERR("Hash mismatch:  %s  (%s)\n", hash, description);
      ERR("         Real: [%s]\n", real_hash);
      return false;
    }
  }

  int log_fd = openat(state->log_dir->fd(), hash, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (log_fd < 0)
    FATAL("Cannot write log data: %s.\n", strerror(errno));
  write(log_fd, &state->log_shm->begin()[HASH_CHARS], MUTATOR_MAX_LOG_BYTES);
  close(log_fd);

  return true;
}

void *afl_custom_init(/*afl_state_t*/ void *afl_, unsigned int seed_) {
  DEBUG_TRACE_FUNC;
  (void) afl_;
  (void) seed_;

  init_error_logging();

  struct mutator_state *state = (struct mutator_state *)calloc(1, sizeof(*state));
  state->variables_shm = new mutator_shm(
    MUTATOR_SHM_VARS_ENV_NAME,
    MUTATOR_SHM_VARS_BYTES, 2 * MUTATOR_SHM_VARS_BYTES);
  state->log_shm = new mutator_shm(
    MUTATOR_SHM_LOG_ENV_NAME,
    MUTATOR_SHM_LOG_BYTES, MUTATOR_SHM_LOG_BYTES);
  state->log_dir = new mutator_temp_dir("/tmp/afl-mutator-XXXXXX");

  return state;
}

uint32_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size) {
  DECL_WITH_TYPE(struct mutator_state, state, data);
  DEBUG_TRACE_FUNC;

  // Input is loaded by afl_custom_queue_get()
  bool has_log = load_log(state, &state->current_log, state->input, state->input_length);
  state->current_mutation = 0;

  state->best_effort_mode = !has_log;
  state->record_log_next_action = has_log ? mutator_state::RECORD_LOG_NONE : mutator_state::RECORD_LOG_PREPARE_INPUT;

  if (state->best_effort_mode) {
    ERR("  %zu bytes, recording log...\n", buf_size);
    return num_best_effort_iterations;
  }

  unsigned num_mutations = 0;
  num_mutations += state->current_log.num_offsets;
  num_mutations += state->current_log.num_offsets * num_splices;
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
    load_log(state, &state->current_log, state->input, state->input_length);
    state->record_log_next_action = mutator_state::RECORD_LOG_NONE;
  case mutator_state::RECORD_LOG_CAPTURE_LOG_AS_IS:
    ERR("Trying to save log as-is...\n");
    if (!save_log_from_shm(state, NULL, 0, "best effort mode"))
      abort();
    accumulate_important_data(state);
    state->record_log_next_action = mutator_state::RECORD_LOG_NONE;
    break;
  }

  unsigned num_offsets = state->current_log.num_offsets;

  if (state->best_effort_mode) {
    unsigned index = state->current_mutation % num_offsets;
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

  delete state->log_dir;
  delete state->log_shm;
  delete state->variables_shm;
  delete state;

  if (error_log)
    fclose(error_log);
}
