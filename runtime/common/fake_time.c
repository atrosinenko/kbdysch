// Rename the original functions to ignore subtle differences in function
// prototypes such as usage of __restrict.
#define clock_gettime clock_gettime_real
#define gettimeofday gettimeofday_real
#define time time_real

#include "kbdysch.h"
#include <stdint.h>
#include <sys/time.h>

#undef clock_gettime
#undef gettimeofday
#undef time

/* *** NO `#include`s BELOW THIS LINE *** */

// Default = Jan 1 00:00:00 UTC 2021
DECLARE_INT_KNOB_DEF(start_time, "START_TIME_SEC", 1609459200);
DECLARE_INT_KNOB_DEF(increment_usec, "INCREMENT_USEC", 1000);

static uint64_t current_offset_usec = 0;

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  current_offset_usec += increment_usec;
  tv->tv_sec  = start_time + current_offset_usec / 1000000;
  tv->tv_usec = current_offset_usec % 1000000;
  return 0;
}

int clock_gettime(clockid_t clockid, struct timespec *tp) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  tp->tv_sec  = tv.tv_sec;
  tp->tv_nsec = tv.tv_usec * 1000;
  return 0;
}

time_t time(time_t *tloc) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  if (tloc)
    *tloc = tv.tv_sec;
  return tv.tv_sec;
}
