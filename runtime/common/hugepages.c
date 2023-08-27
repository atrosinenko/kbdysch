#include "kbdysch/kbdysch.h"
#include "kbdysch/logging.h"

#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>

struct mapping_info {
  uintptr_t begin;
  uintptr_t end;
};

#define MAX_HUGETLB_MAPPINGS 32
static volatile struct mapping_info hugetlb_mappings[MAX_HUGETLB_MAPPINGS];
static volatile int num_hugetlb_mappings = 0;

// Guard against obscure SIGBUS ADRERR when not enough hugepages are available.
//
// NB:  It is possible that after seemingly succeeded invocation of
//          sysctl vm.nr_hugepages=N
//      an actual number of available hugepages returned by
//          sysctl vm.nr_hugepages
//      may be *less* than N.

static void sigbus_action(int sig, siginfo_t *info, void *ucontext) {
  uintptr_t addr = (uintptr_t)info->si_addr;
  for (int i = 0; i < num_hugetlb_mappings; ++i) {
    if (hugetlb_mappings[i].begin <= addr &&
        addr < hugetlb_mappings[i].end) {
      // Use async-signal-safe functions to print the message
      const char msg[] =
          "A signal occurred when accessing a HugeTLB mapping.\n"
          "Maybe not enough hugepages are available.\n";
      write(STDERR_FILENO, &msg, sizeof(msg));
      abort();
    }
  }
}

static void register_mapping(void *ptr, size_t size) {
  if (num_hugetlb_mappings == 0) {
    struct sigaction act = {0};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &sigbus_action;
    CHECK_THAT(0 == sigaction(SIGBUS, &act, NULL));
    CHECK_THAT(0 == sigaction(SIGSEGV, &act, NULL));
  }

  hugetlb_mappings[num_hugetlb_mappings].begin = (uintptr_t)ptr;
  hugetlb_mappings[num_hugetlb_mappings].end = (uintptr_t)ptr + size;
  ++num_hugetlb_mappings;
  CHECK_THAT(num_hugetlb_mappings < MAX_HUGETLB_MAPPINGS);
}

void *map_host_huge_pages_if_possible(struct fuzzer_state *state,
                                      const char *desc, int fd, size_t size) {
  void *result = MAP_FAILED;
  // First, try with HugeTLB enabled to speed up forkserver
  TRACE_NO_NL(state, "Loading %s with HugeTLB (%u KiB)... ", desc, size / 1024);
  result = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
  if (result != MAP_FAILED) {
    TRACE(state, "OK (%p)", result);
    if (fd >= 0)
      CHECK_THAT(pread(fd, result, size, 0) == size);

    register_mapping(result, size);
  } else {
    WARN(state, "Cannot load %s with HugeTLB: %s", desc, strerror(errno));
    TRACE_NO_NL(state, "Loading %s without HugeTLB... ", desc);
    int flags = MAP_PRIVATE;
    if (fd == -1)
      flags |= MAP_ANONYMOUS;
    result = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);
    if (result == MAP_FAILED) {
      LOG_FATAL("Cannot load %s: %s", desc, strerror(errno));
      abort();
    } else {
      TRACE(state, "OK");
    }
  }
  return result;
}
