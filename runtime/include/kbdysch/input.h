#ifndef KBDYSCH_INPUT_H
#define KBDYSCH_INPUT_H

#include <stdint.h>
#include <sys/types.h>

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

#endif  // KBDYSCH_INPUT_H
