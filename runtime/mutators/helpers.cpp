#include "helpers.h"

#include "kbdysch/options.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>

DECLARE_BOOL_KNOB(debug_logging, "KBDYSCH_MUTATOR_DEBUG")

FILE *kbdysch::mutator::error_log;

FILE *kbdysch::mutator::create_temp_file(
    const char *prefix, const char *suffix) {
  char log_name[128];
  sprintf(log_name, "%s%d%s", prefix, getpid(), suffix);
  return fopen(log_name, "w");
}

void kbdysch::mutator::init_error_logging() {
  if (!debug_logging)
    return;

  error_log = create_temp_file("/tmp/kbdysch-mutator-", ".log");
  setvbuf(error_log, NULL, _IONBF, 0);
}

void kbdysch::mutator::deinit_error_logging() {
  if (error_log)
    fclose(error_log);
}

bool kbdysch::mutator::in_mem_area_bounds(
    const void *mem_area, size_t mem_size, const void *ptr, size_t requested_size) {
  uintptr_t mem_start = (uintptr_t)mem_area;
  uintptr_t ptr_start = (uintptr_t)ptr;

  if ((uintptr_t)ptr < (uintptr_t)mem_area) {
    ERR("Pointer %p outside of memory area starting at %p.\n",
        ptr, mem_area);
    return false;
  }
  size_t offset_in_mem_area = (uintptr_t)ptr - (uintptr_t)mem_area;
  if (offset_in_mem_area > mem_size ||
      requested_size > mem_size ||
      offset_in_mem_area + requested_size > mem_size) {
    ERR("Pointer %p at invalid offset 0x%zx in memory area of size 0x%zx.\n",
        ptr, offset_in_mem_area, mem_size);
    return false;
  }
  return true;
}

namespace kbdysch {
namespace mutator {

shm_segment::shm_segment(const char *env_var_name,
                         size_t allocatable_bytes, size_t total_bytes) {
  char id_str[32];
  // Allocate SHM segment
  ShmId = shmget(IPC_PRIVATE, total_bytes, 0600);
  void *shm_segment = shmat(ShmId, NULL, 0);
  AllocatableBuffer = buffer_ref(shm_segment, allocatable_bytes);
  // Make SHM discoverable by harness
  sprintf(id_str, "%d", ShmId);
  setenv(env_var_name, id_str, 1);
}

shm_segment::~shm_segment() {
  shmdt(AllocatableBuffer.bytes());
  shmctl(ShmId, IPC_RMID, NULL);
}

temp_dir::temp_dir(const char *name) {
  strncpy(dir_name, name, MAX_DIR_NAME);
  dir_name[MAX_DIR_NAME - 1] = 0;
  if (!mkdtemp(dir_name))
    FATAL("Cannot create temporary directory %s: %s", dir_name, strerror(errno));

  dir_fd = open(dir_name, O_RDONLY);
  if (dir_fd < 0)
    FATAL("Cannot open directory %s: %s", dir_name, strerror(errno));
}

temp_dir::~temp_dir() {
  close(dir_fd);
  // TODO remove directory
}

ssize_t temp_dir::read_file(const char *name, buffer_ref buf) {
  int file_fd = openat(dir_fd, name, O_RDONLY);
  if (file_fd < 0) {
    ERR("Cannot open file %s for reading: %s\n", name, strerror(errno));
    return -1;
  }

  ssize_t length = read(file_fd, buf.bytes(), buf.size());
  if (length < 0)
    FATAL("Cannot read file %s: %s", name, strerror(errno));

  close(file_fd);
  return length;
}

void temp_dir::write_file(const char *name, buffer_ref buf) {
  int file_fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (file_fd < 0)
    FATAL("Cannot open file %s for writing: %s.\n", name, strerror(errno));
  ssize_t length = write(file_fd, buf.bytes(), buf.size());
  if (length != buf.size())
    FATAL("Cannot write %zu bytes to file %s: %s.\n",
          buf.size(), name, strerror(errno));
  close(file_fd);
}

} // namespace mutator
} // namespace kbdysch
