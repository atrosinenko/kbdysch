#include "kbdysch/base/diagnostics.h"

void check_that_report_fatal_impl(const char *file_name, int line,
                                  const char *expr) {
  FATAL("%s:%d: Check failed: %s", file_name, line, expr);
}
