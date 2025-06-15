#include "kbdysch/extdeps/pth.h"
#include "kbdysch/base/diagnostics.h"

#include <pth.h>
#include <pthread.h>

static void start_lowest_prio_exiter(void);

// Not using __attribute__((constructor)), as it would not be linked into the
// executable unless any function from this object file is *explicitly*
// referenced.

void init_extdep_pth(void) {
  pth_init();
  start_lowest_prio_exiter();
}

static void *exiter_thread_fn(void *arg) {
  pth_nap(pth_time(500, 0));

  fprintf(stderr, "Timeout!\n");
  _exit(0);
  return NULL;
}

static void start_lowest_prio_exiter(void) {
  pth_attr_t attr = pth_attr_new();
  pth_attr_init(attr);
  CHECK_THAT(pth_attr_set(attr, PTH_ATTR_PRIO, PTH_PRIO_MIN));
  pth_spawn(attr, exiter_thread_fn, NULL);
}

void spawn_thread(bool use_pthread, void *(*thread_fn)(void *), void *arg) {
  if (use_pthread) {
    pthread_t thread;
    pthread_create(&thread, NULL, thread_fn, arg);
  } else {
    pth_attr_t attr = pth_attr_new();
    pth_attr_init(attr);
    CHECK_THAT(pth_attr_set(attr, PTH_ATTR_STACK_SIZE, 1024 * 1024));
    pth_spawn(attr, thread_fn, arg);
  }
}
