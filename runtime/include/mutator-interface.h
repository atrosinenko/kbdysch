#ifndef KBDYSCH_MUTATOR_INTERFACE_H
#define KBDYSCH_MUTATOR_INTERFACE_H

#include "common-defs.h"
#include "mutator-defs.h"

typedef struct mutator_fixed_record_header debug_variable;

void mutator_init(void);

debug_variable *mutator_allocate_counters(const char *name, size_t max_counters);

debug_variable *mutator_allocate_strings(const char *name, size_t max_strlen, size_t max_strings);

void *mutator_variable_get_ptr(debug_variable *header, int index);

void mutator_write_trim_offset(unsigned offset);

#define DEBUG_COUNTERS(var_name, description, max_counters) \
  debug_variable *var_name; \
  uint64_t *var_name##_counters; \
  CONSTRUCTOR(init_##var_name) { \
    var_name = mutator_allocate_counters(description, max_counters); \
    var_name##_counters = mutator_variable_get_ptr(var_name, 0); \
  }

#define DEBUG_STRINGS(var_name, description, max_strlen, max_strings) \
  debug_variable *var_name; \
  CONSTRUCTOR(init_##var_name) { \
    var_name = mutator_allocate_strings(description, max_strlen, max_strings); \
  }

#define RESIZE_DEBUG_VARIABLE(var_name, size) \
  if (var_name) var_name->num_elements_mut = (size)

#define INCREMENT_DEBUG_COUNTER(var_name, index, increment) \
  if (var_name##_counters) var_name##_counters[(index)] += (increment)

#endif  // KBDYSCH_MUTATOR_INTERFACE_H
