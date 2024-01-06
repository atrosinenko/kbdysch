#ifndef KBDYSCH_BASE_DIAGNOSTICS_H
#define KBDYSCH_BASE_DIAGNOSTICS_H

#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Before printing the message, put a few newlines: in custom mutator this
// accounts for AFL's own UI and does not hurt in other use cases.
#define FATAL(fmt, ...)                                                       \
  do {                                                                        \
    fprintf(stderr, "\n\n");                                                  \
    fprintf(stderr, "FATAL ERROR at %s:%d\n", __FILE__, __LINE__);            \
    fprintf(stderr, "MESSAGE: " fmt, __VA_ARGS__);                            \
    abort();                                                                  \
  } while (0)

#define FATAL_NOT_IMPLEMENTED(what) FATAL("Not implemented: %s", (what))

#define CHECK_THAT(x)                                                         \
  do {                                                                        \
    if (!(x)) /* no need to inline the cold path */                           \
      check_that_report_fatal_impl(__FILE__, __LINE__, #x);                   \
  } while(0)

void check_that_report_fatal_impl(const char *file_name, int line,
                                  const char *expr);

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_BASE_DIAGNOSTICS_H
