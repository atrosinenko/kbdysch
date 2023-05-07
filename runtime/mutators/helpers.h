#ifndef KBDYSCH_MUTATORS_HELPERS_H
#define KBDYSCH_MUTATORS_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <array>
#include <vector>

namespace kbdysch {
namespace mutator {

extern FILE *error_log;
void init_error_logging();
void deinit_error_logging();

#define DECL_WITH_TYPE(type, new_name, ptr) \
  type *new_name = (type *)(ptr)

#define FATAL(fmt, ...)                                                        \
  do {                                                                         \
    fprintf(stderr, "MUTATOR: %s: %d: " fmt, __FILE__, __LINE__, __VA_ARGS__); \
    abort();                                                                   \
  } while (0)

#define ERR(...)                                         \
  do {                                                   \
    if (kbdysch::mutator::error_log)                     \
      fprintf(kbdysch::mutator::error_log, __VA_ARGS__); \
  } while (0)

#define DEBUG_TRACE_FUNC // fprintf(stderr, "MUTATOR: %s: called\n", __func__)
#define DEBUG(fmt, ...)  // fprintf(stderr, "MUTATOR: %s: " fmt, __func__, __VA_ARGS__)

bool in_mem_area_bounds(const void *mem_area, size_t mem_size,
                        const void *ptr, size_t requested_size);

class buffer_ref {
public:
  buffer_ref()
      : Ptr(0), Size(0) {}

  buffer_ref(void *ptr, size_t size)
      : Ptr((uint8_t *)ptr), Size(size) {}

  template <typename T, std::size_t N>
  buffer_ref(std::array<T, N> &Array)
      : buffer_ref(Array.data(), Array.size()) {}

  template <typename T>
  buffer_ref(std::vector<T> &Vector)
      : buffer_ref(Vector.data(), Vector.size()) {}

  uint8_t *bytes() { return Ptr; }
  const uint8_t *bytes() const { return Ptr; }

  size_t size() const { return Size; }

  bool contains(const void *other_ptr, size_t requested_size) const {
    return in_mem_area_bounds(Ptr, Size, other_ptr, requested_size);
  }

  buffer_ref subbuf(size_t offset, size_t sub_size) {
    return buffer_ref(&Ptr[offset], sub_size);
  }
  const buffer_ref subbuf(size_t offset, size_t sub_size) const {
    return buffer_ref(&Ptr[offset], sub_size);
  }

private:
  uint8_t *Ptr;
  size_t Size;
};

// Array-backed buffer that has a statically-set maximum capacity but
// its logical size can vary from 0 to MaxSize
template <size_t MaxSize>
class array_buffer {
public:
  array_buffer()
      : Size(0) {}

  buffer_ref as_storage() {
    return buffer_ref(Storage);
  }
  const buffer_ref as_storage() const {
    return buffer_ref(Storage);
  }

  buffer_ref as_data() {
    return buffer_ref(Storage).subbuf(0, Size);
  }
  const buffer_ref as_data() const {
    return buffer_ref(Storage).subbuf(0, Size);
  }

  uint8_t *bytes() { return Storage.data(); }
  const uint8_t *bytes() const { return Storage.data(); }

  size_t size() const { return Size; }
  size_t capacity() const { return Storage.size(); }

  void resize(size_t new_size) {
    Size = new_size;
  }

  void memcpy_back(buffer_ref buffer) {
    memcpy(&Storage[Size], buffer.bytes(), buffer.size());
    Size += buffer.size();
  }

  buffer_ref subbuf(size_t offset, size_t sub_size) {
    return buffer_ref(Storage).subbuf(offset, sub_size);
  }
  const buffer_ref subbuf(size_t offset, size_t sub_size) const {
    return buffer_ref(Storage).subbuf(offset, sub_size);
  }

private:
  std::array<uint8_t, MaxSize> Storage;
  size_t Size;
};

inline bool buffer_contains(const buffer_ref buffer,
                            const void *ptr, size_t requested_size) {
  return buffer.contains(ptr, requested_size);
}

class shm_segment {
public:
  shm_segment(const char *env_var_name,
              size_t allocatable_bytes, size_t total_bytes);

  uint8_t *begin() {
    return AllocatableBuffer.bytes();
  }
  const uint8_t *begin() const {
    return AllocatableBuffer.bytes();
  }

  bool in_bounds(const void *ptr, size_t length) const {
    return AllocatableBuffer.contains(ptr, length);
  }

  ~shm_segment();

private:
  int ShmId;
  buffer_ref AllocatableBuffer;
};

class temp_dir {
public:
  temp_dir(const char *name);

  ssize_t read_file(const char *name, buffer_ref buf);
  void write_file(const char *name, buffer_ref buf);

  ~temp_dir();

private:
  static const size_t MAX_DIR_NAME = 128;
  char dir_name[MAX_DIR_NAME];
  int dir_fd;
};

} // namespace mutator
} // namespace kbdysch

#endif // KBDYSCH_MUTATORS_HELPERS_H
