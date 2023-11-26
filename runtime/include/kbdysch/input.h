#ifndef KBDYSCH_INPUT_H
#define KBDYSCH_INPUT_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fuzzer_state;

/**
 * @brief Sets the previously loaded fuzzer input
 */
void res_set_input_data(struct fuzzer_state *state, const uint8_t *data, size_t size);

/**
 * @brief Loads fuzzer testcase from the standard input
 */
void res_load_whole_stdin(struct fuzzer_state *state);

/**
 * @brief Sets current offset in input buffer.
 */
void res_rewind_input(struct fuzzer_state *state, size_t offset);

/**
 * @brief Returns current offset in the fuzzer input data (for debug purposes)
 */
size_t res_get_cur_offset(const struct fuzzer_state *state);

/**
 * @brief Returns the total fuzzer input length (for debug purposes)
 */
ssize_t res_get_input_length(const struct fuzzer_state *state);

/**
 * @brief Returns pointer to the start of input buffer.
 */
const uint8_t *res_get_data_ptr(struct fuzzer_state *state);

/**
 * @brief Explicitly skips enough number of input bytes, so the next position
 * will be aligned as requested
 *
 * @note Some bytes may be skipped implicitly for the alignment purposes as well
 */
void res_align_next_to(struct fuzzer_state *state, size_t alignment);

/**
 * @brief Explicitly skip the specified amount of input bytes
 */
void res_skip_bytes(struct fuzzer_state *state, size_t bytes_to_skip);

/**
 * @brief Reads 1, 2, 4 or 8-bytes size integer from the fuzzer input
 */
uint64_t res_get_uint(struct fuzzer_state *state, size_t size);

/**
 * @brief Copy raw bytes from the input
 *
 * @param state Fuzzer state
 * @param ptr   Pointer to buffer to be filled in
 * @param size  Count of bytes to copy
 */
void res_copy_bytes(struct fuzzer_state *state, void *ptr, size_t size);

static inline unsigned res_get_u8(struct fuzzer_state *state) {
  return res_get_uint(state, 1);
}

static inline unsigned res_get_u16(struct fuzzer_state *state) {
  return res_get_uint(state, 2);
}

static inline unsigned res_get_u32(struct fuzzer_state *state) {
  return res_get_uint(state, 4);
}

static inline uint64_t res_get_u64(struct fuzzer_state *state) {
  return res_get_uint(state, 8);
}

/**
 * Utilify function for mutator interface: call it just before
 * reading the new input section.
 */
void res_mark_section_start(struct fuzzer_state *state);

/**
 * Utilify function for mutator interface: call it right after
 * reading and processing resource reference.
 */
void res_mark_consumed_reference(struct fuzzer_state *state,
                                 int kind, int id, unsigned id_bytes);

/**
 * Utility function for mutator interface: call it right after
 * reading the data to be patched.
 */
void res_propose_change_here(struct fuzzer_state *state,
                             uint64_t replacement, unsigned size);

void res_propose_change_if_different(struct fuzzer_state *state, unsigned offset,
                                     uint64_t replacement, unsigned size);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace kbdysch {

class input_wrapper {
  struct fuzzer_state *State;
  uint64_t ReservedBits;

public:
  explicit input_wrapper(struct fuzzer_state *state)
      : State(state), ReservedBits(0) {}

  unsigned u8() { return res_get_u8(State); }
  unsigned u16() { return res_get_u16(State); }
  unsigned u32() { return res_get_u32(State); }
  uint64_t u64() { return res_get_u64(State); }

  void reserve_bytes(unsigned num_bytes) {
    ReservedBits = res_get_uint(State, num_bytes);
  }

  template <int NumBits>
  uint64_t next_bits() {
    static_assert(NumBits < 64, "Less than 64 bits expected");
    const uint64_t mask = (1ULL << NumBits) - 1ULL;
    uint64_t result = ReservedBits & mask;
    ReservedBits >>= NumBits;
    return result;
  }
};

} // namespace kbdysch

#endif // __cplusplus

#endif  // KBDYSCH_INPUT_H
