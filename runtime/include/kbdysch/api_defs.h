#ifndef KBDYSCH_API_DEFS_H
#define KBDYSCH_API_DEFS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct key_desc {
    char *prefix;
	int8_t id;
	int8_t z;
};

struct cap_data {
    int32_t eff0;
    int32_t perm0;
    int32_t inher0;
    int32_t eff1;
    int32_t perm1;
    int32_t inher1;
};

struct cap_header {
    int32_t var;
	int pid;
};

struct ext4_new_group_input {
    uint32_t group;
    uint64_t block_bitmap;
    uint64_t inode_bitmap;
    uint64_t inode_table;
    uint32_t blocks_count;
    uint16_t reserved_blocks;
    uint64_t unused;
};

struct move_extent {
    uint32_t reserved;
    int donor_fd;
    uint64_t orig_start;
    uint64_t donor_start;
    uint64_t len;
    uint64_t moved_len;
};

struct pipefd {
    int rfd;
    int wfd;
};

struct my_sockaddr_storage {
  uint16_t sa_family;
  uint8_t sa_data[126];
};

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_API_DEFS_H
