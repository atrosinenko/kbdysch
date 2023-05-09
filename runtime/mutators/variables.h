#ifndef KBDYSCH_MUTATORS_VARIABLES_H
#define KBDYSCH_MUTATORS_VARIABLES_H

#include "kbdysch/mutator-defs.h"
#include "helpers.h"

#include <string>

namespace kbdysch {
namespace mutator {

class variable {
public:
  // On success, returns true, updates `variables` and sets `*Ptr` to the next variable to be read.
  // On error, returns false and `*Ptr` is unspecified.
  static bool create_from_shm(std::vector<variable *> &variables,
                              buffer_ref main_area,
                              buffer_ref aux_area,
                              uint8_t **ptr);

  virtual void accumulate() = 0;
  virtual void print(FILE *stream, unsigned var_index);
  unsigned num_elements_real();

  virtual ~variable() {}

protected:
  variable(const std::string &name, unsigned max_num_elements, mutator_num_elements_t *num_elements_real)
      : Name(name), MaxNumElements(max_num_elements), NumElementsReal(num_elements_real) {}

  virtual void print_scalar(FILE *stream, unsigned subscript) = 0;

  std::string Name;

private:
  unsigned MaxNumElements;
  mutator_num_elements_t *NumElementsReal;
};

} // namespace mutator
} // namespace kbdysch

#endif // KBDYSCH_MUTATORS_VARIABLES_H
