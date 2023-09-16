#ifndef KBDYSCH_USERSPACE_FILES_H
#define KBDYSCH_USERSPACE_FILES_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fuzzer_state;
size_t kernel_read_from_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size);
void kernel_dump_file_contents(struct fuzzer_state *state, const char *filename);
void kernel_write_to_file(struct fuzzer_state *state, const char *filename, const void *data, size_t size, int write_may_fail);
void kernel_write_string_to_file(struct fuzzer_state *state, const char *filename, const char *str, int write_may_fail);
void wait_for_fd(struct fuzzer_state *state, int fd, bool for_read, bool for_write);

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_USERSPACE_FILES_H
