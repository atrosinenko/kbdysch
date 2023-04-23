#ifndef KBDYSCH_MUTATORS_MUTATIONS_H
#define KBDYSCH_MUTATORS_MUTATIONS_H

#include "helpers.h"

struct mutator_state;

namespace kbdysch {
namespace mutator {

class mutation_strategy {
public:
  /// Re-initialize for new input data
  virtual void reset(mutator_state *state) = 0;

  virtual unsigned remaining_mutation_count() const = 0;

  virtual void randomize(unsigned seed) = 0;

  virtual void render_next_mutation(mutator_state *state,
                                    uint8_t *add_buf, size_t add_buf_size) = 0;

  virtual ~mutation_strategy() {}
};

} // namespace mutator
} // namespace kbdysch

#endif // KBDYSCH_MUTATORS_MUTATIONS_H
