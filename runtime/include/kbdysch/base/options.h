#ifndef KBDYSCH_BASE_OPTIONS_H
#define KBDYSCH_BASE_OPTIONS_H

#include "kbdysch/base/base-defs.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// \defgroup knobs Retrieving configuration parameters
/// @{

typedef uint64_t bitmask_t;
#define BIT(n) ((bitmask_t)1 << (n))
bool get_bool_knob(const char *name, bool default_value);
bitmask_t get_bitmask_knob(const char *name, bitmask_t default_value);
int get_int_knob(const char *name, int default_value);
const char *get_string_knob(const char *name, const char *default_value);

#define DECLARE_KNOB_DEF(type, getter, name, var, default_value) \
  static type name; \
  CONSTRUCTOR(init_##name) { name = getter(var, default_value); }
#define DECLARE_BOOL_KNOB(name, var) \
  DECLARE_KNOB_DEF(bool, get_bool_knob, name, var, false)
#define DECLARE_BITMASK_KNOB(name, var) \
  DECLARE_KNOB_DEF(bitmask_t, get_bitmask_knob, name, var, 0)
#define DECLARE_INT_KNOB_DEF(name, var, default_value) \
  DECLARE_KNOB_DEF(int, get_int_knob, name, var, default_value)
#define DECLARE_INT_KNOB(name, var) \
  DECLARE_KNOB_DEF(int, get_int_knob, name, var, 0)
#define DECLARE_STRING_KNOB(name, var) \
  DECLARE_KNOB_DEF(const char *, get_string_knob, name, var, NULL)

/// @}

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_BASE_OPTIONS_H
