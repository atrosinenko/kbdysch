#ifndef KBDYSCH_MUTATORS_JOURNAL_H
#define KBDYSCH_MUTATORS_JOURNAL_H

#include "kbdysch/mutator-defs.h"
#include "helpers.h"

#include <stdint.h>

#include <array>
#include <vector>

namespace kbdysch {
namespace mutator {

struct section_bounds {
  unsigned begin;
  unsigned end;

  unsigned size() const { return end - begin; }
};

struct resource_reference {
  mutator_log_ref_resource reference;
  unsigned using_section;
  unsigned defining_section;
};

class journal_data {
public:
  explicit journal_data(temp_dir &dir);

  // Try loading journal for input_data.
  bool load_journal(const buffer_ref input_data);

  // section index 0 is kind of implicit header:
  // set_offset       v   v
  // file       [-----|---|--- ...
  // index         0    1   2
  const std::vector<section_bounds> &sections() const { return Sections; }

  const std::vector<resource_reference> &resource_references() const {
    return References;
  }

  unsigned defining_section(unsigned kind, unsigned id) const {
    return DefiningSections[kind][id];
  }

  const std::vector<mutator_log_propose_change> &proposals() const {
    return Proposals;
  }

private:
  bool read_journal_from_disk(const buffer_ref input_data);
  bool parse_journal(unsigned input_bytes);

  bool find_next_record(unsigned &opaque_offset, unsigned &record_type, const void *&payload);

  temp_dir &JournalDir;
  std::array<uint8_t, MUTATOR_MAX_LOG_BYTES> RawLog;

  // Using statically set sizes to prevent mutator crash due to misbehaving harness
  std::array<std::array<unsigned, MUTATOR_MAX_RESOURCE_IDS>, MUTATOR_MAX_RESOURCE_KINDS> DefiningSections;

  // Sizes are implicitly bound by maximum journal size
  std::vector<section_bounds> Sections;
  std::vector<resource_reference> References;
  std::vector<mutator_log_propose_change> Proposals;
};

} // namespace mutator
} // namespace kbdysch

#endif // KBDYSCH_MUTATORS_JOURNAL_H
