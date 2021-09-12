#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

#define _GNU_SOURCE

// Hack preventing LKL's BPF definitions from interfering with host ones
#define __LKL__LINUX_BPF_H__
union lkl_bpf_attr;

#include <stdbool.h>
#include <stdint.h>
#include <memory.h>

#define LKL_HAS_STATX_SYSCALL 1

#define MAX_PART_COUNT 10

#define MAX_INPUT_LEN (1 << 16)
#define MAX_BUFFER_LEN (1 << 20)
#define MAX_FILE_NAME_LEN (1 << 16)
#define MAX_STRING_LEN (1 << 16)

// Put N predefined bytes right after the allocated buffer
#define WATERMARK_SIZE 32

struct fuzzer_state;

typedef char filename_t[MAX_FILE_NAME_LEN];
typedef char string_t[MAX_STRING_LEN];
typedef uint8_t buffer_t[MAX_BUFFER_LEN + WATERMARK_SIZE];

#define CONSTRUCTOR(unique_name) \
  static void __attribute__((constructor)) unique_name(void)

#endif // COMMON_DEFS_H
