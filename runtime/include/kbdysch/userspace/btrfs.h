#ifndef KBDYSCH_USERSPACE_BTRFS_H
#define KBDYSCH_USERSPACE_BTRFS_H

#ifdef __cplusplus
extern "C" {
#endif

struct fuzzer_state;
void kbdysch_btrfs_maintainance(struct fuzzer_state *state, int part_idx);

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_USERSPACE_BTRFS_H
