#ifndef KBDYSCH_MUTATORS_MUTATIONS_H
#define KBDYSCH_MUTATORS_MUTATIONS_H

#include "kbdysch/mutator-defs.h"
#include "helpers.h"

namespace kbdysch {
namespace mutator {

typedef array_buffer<MUTATOR_MAX_TEST_CASE_LENGTH> test_case_storage;

class journal_data;

class mutation_strategy {
protected:
  explicit mutation_strategy(bool needs_add_buf)
      : NeedsAddBuf(needs_add_buf) {}

public:
  /// Re-initialize for new input data
  virtual void reset(buffer_ref input, journal_data &input_journal) = 0;

  virtual unsigned remaining_mutation_count() const = 0;

  virtual void randomize(unsigned seed) = 0;

  bool needs_add_buf() const { return NeedsAddBuf; }

  // Reimplement if needs_add_buf() returns false
  virtual void render_next_mutation(test_case_storage &output,
                                    buffer_ref input, journal_data &input_journal) {
    abort();
  }

  // Reimplement if needs_add_buf() returns true
  virtual void render_next_mutation(test_case_storage &output,
                                    buffer_ref input, journal_data &input_journal,
                                    buffer_ref add_buf, journal_data &add_journal) {
    abort();
  }

  virtual ~mutation_strategy() {}

private:
  bool NeedsAddBuf;
};

void populate_mutation_strategies(std::vector<mutation_strategy *> &strategies);

} // namespace mutator
} // namespace kbdysch

#endif // KBDYSCH_MUTATORS_MUTATIONS_H
