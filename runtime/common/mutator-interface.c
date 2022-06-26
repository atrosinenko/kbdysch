#include "mutator-interface.h"
#include "mutator-defs.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/shm.h>

#define WORD_SIZE sizeof(mutator_shm_word)
#define NUM_WORDS(bytes) (((bytes) + WORD_SIZE - 1) / WORD_SIZE)

static bool initialized;
static bool fixed_size_buffer_closed;
static mutator_shm_word *shm_words;
static unsigned current_word;

void mutator_init(void) {
  if (initialized)
    return;
  initialized = true;

  const char *shm_str = getenv(MUTATOR_ENV_NAME);
  if (!shm_str)
    return;

  shm_words = shmat(atoi(shm_str), NULL, 0);
  current_word = 0;
}

static void *allocate_in_shm(size_t bytes, size_t extra_words) {
  if (!initialized)
    mutator_init();

  if (!shm_words)
    return NULL;

  size_t words = NUM_WORDS(bytes);
  if (current_word + words + extra_words > MUTATOR_SHM_SIZE_WORDS)
    return NULL;

  void *result = &shm_words[current_word];
  memset(result, 0, WORD_SIZE * words);
  current_word += words;

  return result;
}

#define ALLOC_SHM_VAR(type, name) \
  type *name = (type *)allocate_in_shm(sizeof(type), 0)

static struct mutator_fixed_record_header *allocate_fixed_record(
    int type, const char *name, size_t element_words, size_t max_elements) {
  assert(!fixed_size_buffer_closed);

  size_t name_bytes = strlen(name);

  ALLOC_SHM_VAR(struct mutator_fixed_record_header, header);
  if (!header)
    return NULL;

  header->type = type;
  header->name_words = NUM_WORDS(name_bytes);
  header->element_words = element_words;
  header->max_num_elements = max_elements;

  char *name_var = allocate_in_shm(name_bytes, 0);
  if (!name_var)
    return NULL;
  memcpy(name_var, name, name_bytes);

  allocate_in_shm(WORD_SIZE * element_words * max_elements, 0);

  return header;
}

debug_variable *mutator_allocate_counters(const char *name, size_t max_counters) {
  return allocate_fixed_record(MUTATOR_FIXED_RECORD_COUNTERS, name,
                               NUM_WORDS(sizeof(uint64_t)), max_counters);
}

debug_variable *mutator_allocate_strings(const char *name, size_t max_strlen, size_t max_strings) {
  return allocate_fixed_record(MUTATOR_FIXED_RECORD_STRINGS, name,
                               NUM_WORDS(max_strlen), max_strings);
}

void close_fixed_section(void) {
  assert(initialized);
  if (!shm_words)
    return;
  fixed_size_buffer_closed = true;
  allocate_fixed_record(MUTATOR_FIXED_RECORD_STOP, "END", 0, 0);
  mutator_shm_word *mark = allocate_in_shm(WORD_SIZE, 1);
  if (!mark)
    return;
  *mark = MUTATOR_END_OF_FIXED_SECTION_MARK;
}

void *mutator_variable_get_ptr(debug_variable *header, int index) {
  if (!header)
    return NULL;

  uint8_t *ptr = (uint8_t *)header;
  ptr += sizeof(struct mutator_fixed_record_header);
  ptr += WORD_SIZE * header->name_words;
  ptr += WORD_SIZE * header->element_words * index;
  return ptr;
}

static void mutator_put_insn(unsigned opcode, unsigned *args, unsigned num_args) {
  assert(initialized);
  if (!fixed_size_buffer_closed)
    close_fixed_section();
  mutator_shm_word *words = allocate_in_shm((1 + num_args) * WORD_SIZE, 2);
  if (!words)
    return;

  words[0] = opcode;
  for (unsigned i = 0; i < num_args; ++i)
    words[1 + i] = args[i];
  // to be overwritten
  words[1 + num_args] = MUTATOR_OPCODE_STOP;
  words[2 + num_args] = MUTATOR_END_OF_BYTECODE_SECTION_MARK;
}

void mutator_write_trim_offset(unsigned offset) {
  unsigned args[] = {offset};
  mutator_put_insn(MUTATOR_OPCODE_SET_OFFSET, args, 1);
}
