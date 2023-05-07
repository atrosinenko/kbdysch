#ifndef KBDYSCH_MUTATOR_INTERFACE_H
#define KBDYSCH_MUTATOR_INTERFACE_H

#include "kbdysch/common-defs.h"
#include "kbdysch/mutator-defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mutator_var_header debug_variable;

void mutator_init(void);

debug_variable *mutator_allocate_counters(const char *name, size_t max_counters);

debug_variable *mutator_allocate_strings(const char *name, size_t max_strlen, size_t max_strings);

void mutator_init_input(struct fuzzer_state *state);

void *mutator_variable_get_ptr(debug_variable *header, int index);

void mutator_write_trim_offset(unsigned offset);

void mutator_open_resource(unsigned kind, unsigned id);
void mutator_ref_resource(unsigned kind, unsigned id, unsigned id_bytes, unsigned offset);
void mutator_propose_change(unsigned offset, uint64_t replacement, unsigned size);

#define DEBUG_COUNTERS(var_name, description, max_counters) \
  debug_variable *var_name; \
  uint64_t *var_name##_counters; \
  CONSTRUCTOR(init_##var_name) { \
    var_name = mutator_allocate_counters(description, max_counters); \
    var_name##_counters = mutator_variable_get_ptr(var_name, 0); \
  }

#define DEBUG_COUNTER(var_name, description) \
  uint64_t *var_name##_counters; \
  CONSTRUCTOR(init_##var_name) { \
    debug_variable *var_name = mutator_allocate_counters(description, 1); \
    var_name##_counters = mutator_variable_get_ptr(var_name, 0); \
    RESIZE_DEBUG_VARIABLE(var_name, 1); \
  }

#define DEBUG_STRINGS(var_name, description, max_strlen, max_strings) \
  debug_variable *var_name; \
  CONSTRUCTOR(init_##var_name) { \
    var_name = mutator_allocate_strings(description, max_strlen, max_strings); \
  }

#define RESIZE_DEBUG_VARIABLE(var_name, size) \
  if (var_name) var_name->num_elements_real = (size)

#define INCREMENT_DEBUG_COUNTER(var_name, index, increment) \
  if (var_name##_counters) { \
    mutator_u64_var_t *counter = &var_name##_counters[(index)]; \
    mutator_u64_var_t *counter_current = (mutator_u64_var_t *)MUTATOR_SHM_VAR_IN_CURRENT_AREA(counter); \
    unsigned inc = (increment); \
    *counter += inc; \
    *counter_current += inc; \
  }

#define DEBUG_INC(var_name) INCREMENT_DEBUG_COUNTER(var_name, 0, 1)

#ifdef __cplusplus
}
#endif

#endif  // KBDYSCH_MUTATOR_INTERFACE_H
