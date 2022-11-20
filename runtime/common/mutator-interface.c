#include "kbdysch/mutator-interface.h"
#include "kbdysch/mutator-defs.h"
#include "kbdysch/hashing.h"
#include "kbdysch/logging.h"

// FIXME factor out: input-data.h
#include "kbdysch/invoker-utils.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/shm.h>

struct mutator_shm {
  uint8_t *shm_segment;
  unsigned offset;
  size_t allocatable_bytes;
};

static bool initialized;
static struct mutator_shm vars_shm;
static struct mutator_shm log_shm;

static void get_shm_segment(struct mutator_shm *shm, const char *env_name,
                            size_t allocatable_bytes, size_t total_bytes) {
  shm->offset = 0;
  shm->allocatable_bytes = allocatable_bytes;

  const char *shm_id_str = getenv(env_name);
  if (!shm_id_str) {
    WARN(NULL, "%s variable not found, allocating dummy segment", env_name);
    shm->shm_segment = malloc(total_bytes);
    return;
  }

  int shm_id = atoi(shm_id_str);
  shm->shm_segment = shmat(shm_id, NULL, 0);
  CHECK_THAT(shm->shm_segment != (void *)-1);
}

static uint8_t *alloc_in_shm(struct mutator_shm *shm, size_t size, size_t extra_bytes) {
  if (shm->offset + size + extra_bytes > shm->allocatable_bytes)
    return NULL;

  uint8_t *result = &shm->shm_segment[shm->offset];
  shm->offset += size;
  memset(result, 0, size + extra_bytes);

  return result;
}

void mutator_init(void) {
  if (initialized)
    return;
  initialized = true;

  get_shm_segment(&vars_shm, MUTATOR_SHM_VARS_ENV_NAME,
                  MUTATOR_SHM_VARS_BYTES, 2 * MUTATOR_SHM_VARS_BYTES);
  get_shm_segment(&log_shm, MUTATOR_SHM_LOG_ENV_NAME,
                  MUTATOR_SHM_LOG_BYTES, MUTATOR_SHM_LOG_BYTES);
  TRACE(NULL, "Mutator interface initialized");
}

void mutator_init_input(struct fuzzer_state *state) {
  char hash[HASH_CHARS + 1];
  kbdysch_compute_hash(hash, res_get_data_ptr(state), res_get_input_length(state));
  hash[HASH_CHARS] = '\0';

  void *ptr = alloc_in_shm(&log_shm, HASH_CHARS, sizeof(struct mutator_log_record_header));
  memcpy(ptr, hash, HASH_CHARS);
  memset(&vars_shm.shm_segment[MUTATOR_SHM_VARS_BYTES], 0, MUTATOR_SHM_VARS_BYTES);
  TRACE(state, "Mutator input initialized, hash: %s", hash);
}

static struct mutator_var_header *allocate_mutator_var(
    int type, const char *name, size_t bytes_per_element, size_t max_elements) {

  mutator_init();

  struct mutator_var_header *header;

  size_t name_bytes = strlen(name);
  size_t elements_offset = sizeof(*header) + name_bytes;
  size_t elements_bytes = bytes_per_element * max_elements;

  unsigned total_bytes = sizeof(*header) + name_bytes + elements_bytes;

  uint8_t *raw_header_ptr = alloc_in_shm(&vars_shm, total_bytes, sizeof(*header));
  header = (struct mutator_var_header *)raw_header_ptr;
  if (!header)
    return NULL;

  header->type = type;
  header->name_bytes = name_bytes;
  header->bytes_per_element = bytes_per_element;
  header->max_num_elements = max_elements;

  memcpy(&raw_header_ptr[sizeof(*header)], name, name_bytes);

  return header;
}

debug_variable *mutator_allocate_counters(const char *name, size_t max_counters) {
  return allocate_mutator_var(MUTATOR_VAR_COUNTERS, name, sizeof(uint64_t), max_counters);
}

debug_variable *mutator_allocate_strings(const char *name, size_t max_strlen, size_t max_strings) {
  return allocate_mutator_var(MUTATOR_VAR_STRINGS, name, max_strlen, max_strings);
}

void *mutator_variable_get_ptr(debug_variable *header, int index) {
  if (!header)
    return NULL;

  uint8_t *ptr = (uint8_t *)header;
  ptr += sizeof(struct mutator_var_header);
  ptr += header->name_bytes;
  ptr += header->bytes_per_element * index;
  return ptr;
}

static void *alloc_log_impl(unsigned type, size_t payload_size) {
  struct mutator_log_record_header *header;
  size_t total_bytes = sizeof(*header) + payload_size;
  uint8_t *raw_header_ptr = alloc_in_shm(&log_shm, total_bytes, sizeof(*header));
  if (!raw_header_ptr)
    return NULL;

  header = (struct mutator_log_record_header *)raw_header_ptr;

  header->type = type;
  header->size = total_bytes;

  return &raw_header_ptr[sizeof(*header)];
}

#define ALLOC_LOG_PAYLOAD(record_type_id, var_type) \
    var_type *payload = (var_type *)alloc_log_impl(record_type_id, sizeof(var_type)); \
    if (!payload) return;

void mutator_write_trim_offset(unsigned offset) {
  ALLOC_LOG_PAYLOAD(MUTATOR_LOG_SET_OFFSET, struct mutator_log_set_offset);
  payload->offset = offset;
}

void mutator_open_resource(unsigned kind, unsigned id) {
  ALLOC_LOG_PAYLOAD(MUTATOR_LOG_NEW_RES, struct mutator_log_new_resource);
  payload->kind = kind;
  payload->id = id;
}

void mutator_ref_resource(unsigned kind, unsigned id, unsigned id_bytes, unsigned offset) {
  ALLOC_LOG_PAYLOAD(MUTATOR_LOG_REF_RES, struct mutator_log_ref_resource);
  payload->kind = kind;
  payload->id = id;
  payload->id_bytes = id_bytes;
  payload->offset = offset;
}
