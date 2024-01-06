#include "mutations.h"

#include "kbdysch/base/options.h"
#include "journal.h"

#include <assert.h>

DECLARE_INT_KNOB_DEF(num_splices, "KBDYSCH_MUTATOR_NUM_SPLICES", 4)

namespace kbdysch {
namespace mutator {

class section_dropper : public mutation_strategy {
public:
  section_dropper()
      : mutation_strategy(false) {}

  void reset(buffer_ref input, journal_data &input_journal) override {
    current_mutation = 0;
    // 0-th section is never dropped
    total_mutations = input_journal.sections().size() - 1;
  }

  unsigned remaining_mutation_count() const override {
    return total_mutations - current_mutation;
  }

  void randomize(unsigned seed) override {
    current_mutation = seed % total_mutations;
  }

  void render_next_mutation(test_case_storage &output,
                            buffer_ref input, journal_data &input_journal) override;

private:
  std::vector<bool> skipped_sections;
  unsigned current_mutation;
  unsigned total_mutations;
};

void section_dropper::render_next_mutation(
    test_case_storage &output,
    buffer_ref input, journal_data &input_journal) {
  const auto &sections = input_journal.sections();
  const auto &references = input_journal.resource_references();
  const unsigned num_sections = sections.size();

  skipped_sections.assign(sections.size(), false);
  skipped_sections[current_mutation + 1] = true;
  ++current_mutation;

  for (const auto &ref : references) {
    if (ref.defining_section >= num_sections ||
        ref.using_section >= num_sections) {
      ERR("Unexpected reference: defines %u / uses %u (total %u)\n",
          ref.defining_section, ref.using_section, num_sections);
      continue;
    }
    if (skipped_sections[ref.defining_section])
      skipped_sections[ref.using_section] = true;
  }

  auto cur_reference = references.begin();
  for (int section_idx = 0; section_idx < num_sections; ++section_idx) {
    const auto &cur_section = sections[section_idx];

    while (cur_reference != references.end() &&
           cur_reference->using_section < section_idx)
      ++cur_reference;

    if (skipped_sections[section_idx])
      continue;

    unsigned output_section_offset = output.size();
    output.memcpy_back(input.subbuf(cur_section.begin, cur_section.size()));

    while (cur_reference != references.end() &&
           cur_reference->using_section == section_idx) {
      unsigned kind = cur_reference->reference.kind;
      unsigned id = cur_reference->reference.id;
      unsigned size = cur_reference->reference.id_bytes;

      unsigned offset = cur_reference->reference.offset;
      offset -= cur_section.begin - output_section_offset;

      uint8_t *patched_id = &output.bytes()[offset];
      uint64_t new_id = 0;
      memcpy(&new_id, patched_id, size);
      for (unsigned i = 0; i < id; ++i) {
        unsigned def_section = input_journal.defining_section(kind, i);
        if (def_section < num_sections && skipped_sections[def_section])
          --new_id;
      }
      memcpy(patched_id, &new_id, size);

      ++cur_reference;
    }
  }
}

class test_case_splicer : public mutation_strategy {
public:
  test_case_splicer()
      : mutation_strategy(true) {}

  void reset(buffer_ref input, journal_data &input_journal) override {
    current_mutation = 0;
    num_sections = input_journal.sections().size();
  }

  unsigned remaining_mutation_count() const override {
    return num_sections * num_splices - current_mutation;
  }

  void randomize(unsigned seed) override {
    current_mutation = seed % (num_sections * num_splices);
  }

  void render_next_mutation(test_case_storage &output,
                            buffer_ref input, journal_data &input_journal,
                            buffer_ref add_buf, journal_data &add_journal) override;

private:
  unsigned current_mutation;
  unsigned num_sections;
};

void test_case_splicer::render_next_mutation(
    test_case_storage &output,
    buffer_ref input, journal_data &input_journal,
    buffer_ref add_buf, journal_data &add_journal) {
  const auto &sections = input_journal.sections();
  const auto &other_sections = add_journal.sections();
  unsigned num_prefix_sections = current_mutation / num_splices;
  unsigned prefix_length = sections[num_prefix_sections].end;
  ++current_mutation;

  unsigned additional_index = random() & 0xFFFF;
  additional_index %= other_sections.size();
  unsigned suffix_start = other_sections[additional_index].begin;
  unsigned suffix_length = std::min<unsigned>(
      add_buf.size() - suffix_start,
      MUTATOR_MAX_TEST_CASE_LENGTH - prefix_length);

  output.memcpy_back(input.subbuf(0, prefix_length));
  output.memcpy_back(add_buf.subbuf(suffix_start, suffix_length));
}

class proposal_applier : public mutation_strategy {
public:
  proposal_applier()
      : mutation_strategy(false) {}

  void reset(buffer_ref input, journal_data &input_journal) override {
    current_mutation = 0;
    num_proposals = input_journal.proposals().size();
  }

  unsigned remaining_mutation_count() const override {
    return num_proposals - current_mutation;
  }

  void randomize(unsigned seed) override {
    current_mutation = seed % num_proposals;
  }

  void render_next_mutation(test_case_storage &output,
                            buffer_ref input, journal_data &input_journal) override;

private:
  unsigned current_mutation;
  unsigned num_proposals;
};

void proposal_applier::render_next_mutation(
    test_case_storage &output,
    buffer_ref input, journal_data &input_journal) {
  const auto &proposal = input_journal.proposals()[current_mutation++];

  unsigned offset = proposal.offset;
  unsigned size = proposal.size;

  output.memcpy_back(input);
  uint8_t *patched_data = &output.bytes()[offset];
  memcpy(patched_data, &proposal.replacement, size);
}

void populate_mutation_strategies(std::vector<mutation_strategy *> &strategies) {
  strategies.push_back(new section_dropper());
  strategies.push_back(new test_case_splicer());
  strategies.push_back(new proposal_applier());
}

} // namespace mutator
} // namespace kbdysch
