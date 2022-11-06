#ifndef KBDYSCH_AFL_INTERFACE_DECLS_H
#define KBDYSCH_AFL_INTERFACE_DECLS_H

#include <stddef.h>
#include <stdint.h>

void *afl_custom_init(/*afl_state_t*/ void *afl_, unsigned int seed_);
void afl_custom_deinit(void *data);

uint8_t afl_custom_queue_get(void *data, const char *filename);
uint8_t afl_custom_queue_new_entry(void *data, const char *filename_new_queue,
                                   const char *filename_orig_queue);

uint32_t afl_custom_fuzz_count(void *data, const uint8_t *buf, size_t buf_size);
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size);

#endif // KBDYSCH_AFL_INTERFACE_DECLS_H
