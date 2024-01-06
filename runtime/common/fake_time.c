// Rename the original functions to ignore subtle differences in function
// prototypes such as usage of __restrict.
#define clock_gettime clock_gettime_real
#define gettimeofday gettimeofday_real
#define time time_real
#define select select_real

#include "kbdysch/base/options.h"
#include "kbdysch/kbdysch.h"
#include <stdint.h>
#include <time.h>
#include <dlfcn.h>

#undef clock_gettime
#undef gettimeofday
#undef time
#undef select

/* *** NO `#include`s BELOW THIS LINE *** */

// Start time = Jan 1 00:00:00 UTC 2021
// Set it statically to prevent 50-year-long jump during initialization.
// This jump makes libpth hang in `pth_scheduler_load` if its constructors
// were called before `START_TIME` was initialized.
const uint64_t START_TIME = 1609459200;
DECLARE_INT_KNOB_DEF(increment_usec, "INCREMENT_USEC", 1000);

static uint64_t current_offset_usec = 0;

static inline void tick() {
  current_offset_usec += increment_usec;
}

static inline uint64_t monotonic_sec() {
  return current_offset_usec / UINT64_C(1000000);
}

static inline uint64_t realtime_sec() {
  return START_TIME + monotonic_sec();
}

static inline uint64_t usec() {
  return current_offset_usec % UINT64_C(1000000);
}

struct timezone;

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  tick();
  tv->tv_sec  = realtime_sec();
  tv->tv_usec = usec();
  return 0;
}

int clock_gettime(clockid_t clockid, struct timespec *tp) {
  tick();
  switch (clockid) {
  case CLOCK_REALTIME:
    tp->tv_sec  = realtime_sec();
    tp->tv_nsec = usec() * 1000;
    break;
  case CLOCK_MONOTONIC:
    tp->tv_sec = monotonic_sec();
    tp->tv_nsec = usec() * 1000;
    break;
  default:
    LOG_FATAL("Unhandled clockid: %d", clockid);
    abort();
  }
  return 0;
}

time_t time(time_t *tloc) {
  tick();
  uint64_t result = realtime_sec();
  if (tloc)
    *tloc = result;
  return result;
}

int (*select_original)(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, struct timeval *timeout);

CONSTRUCTOR(dlsym_select) {
  select_original = dlsym(RTLD_NEXT, "select");
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout) {
  if (timeout) {
    current_offset_usec += timeout->tv_sec * 1000000u;
    current_offset_usec += timeout->tv_usec;
    timeout->tv_sec = 0;
    timeout->tv_usec = 0;
  }
  return select_original(nfds, readfds, writefds, exceptfds, timeout);
}
