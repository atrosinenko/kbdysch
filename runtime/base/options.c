#include "kbdysch/base/options.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static const char *get_config(const char *name) {
  const char *result = getenv(name);
  const char *printed = result ? result : "<default>";
  fprintf(stderr, "config: %s = %s\n", name, printed);
  return result;
}

bool get_bool_knob(const char *name, bool default_value) {
  return get_config(name) ? true : default_value;
}

bitmask_t get_bitmask_knob(const char *name, bitmask_t default_value) {
  const char *str = get_config(name);
  assert(sizeof(bitmask_t) <= sizeof(long long));
  return str ? ((bitmask_t)strtoll(str, NULL, 0)) : default_value;
}

int get_int_knob(const char *name, int default_value) {
  const char *str = get_config(name);
  return str ? ((int)strtol(str, NULL, 0)) : default_value;
}

const char *get_string_knob(const char *name, const char *default_value) {
  const char *str = get_config(name);
  return str ? str : default_value;
}
