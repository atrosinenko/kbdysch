#include "variables.h"
#include "kbdysch/mutator-defs.h"
#include "helpers.h"

#include <assert.h>

#include <algorithm>
#include <cmath>
#include <functional>
#include <iomanip>
#include <utility>
#include <vector>

namespace kbdysch {
namespace mutator {

class counter_variable : public variable {
public:
  counter_variable(std::string &&name,
                   unsigned max_num_elements,
                   mutator_num_elements_t *num_elements_real,
                   mutator_u64_var_t *counters,
                   mutator_u64_var_t *aux_counters)
      : variable(name, max_num_elements, num_elements_real),
        Counters(counters), AuxCounters(aux_counters) {
    Accumulator.assign(max_num_elements, 0);
  }

  void accumulate() override;
  void print_scalar(std::ostringstream &stream, unsigned subscript) override {
    stream << Counters[subscript] << "\t" << Accumulator[subscript];
  }

  uint64_t get(unsigned index) const { return Counters[index]; }
  uint64_t get_accumulated(unsigned index) const { return Accumulator[index]; }

private:
  mutator_u64_var_t *Counters;
  mutator_u64_var_t *AuxCounters;
  std::vector<uint64_t> Accumulator;
};

void counter_variable::accumulate() {
  for (unsigned i = 0; i < Accumulator.size(); ++i)
    Accumulator[i] += AuxCounters[i];
}

class string_variable : public variable {
public:
  string_variable(std::string &&name,
                  unsigned max_num_elements,
                  mutator_num_elements_t *num_elements_real,
                  std::vector<char *> &&strings,
                  unsigned max_string_length)
      : variable(name, max_num_elements, num_elements_real),
        Strings(strings), MaxStringLength(max_string_length) {}

  void accumulate() override {}

  void print_scalar(std::ostringstream &stream, unsigned subscript) override {
    char *str = Strings[subscript];
    str[MaxStringLength - 1] = '\0';
    stream << str;
  }

private:
  std::vector<char *> Strings;
  unsigned MaxStringLength;
};

class success_rate_variable : public variable {
public:
  success_rate_variable(std::string &&name,
                        string_variable *labels,
                        counter_variable *success,
                        counter_variable *failure)
      : variable(name, 0, 0), Labels(labels), Success(success), Failure(failure) {}

  void accumulate() override;

  void print(FILE *stream, unsigned var_index) override;

  ~success_rate_variable();

protected:
  void print_scalar(std::ostringstream &stream, unsigned subscript) override {
    abort(); // Not implemented
  }

private:
  void print_label_with_rank(std::ostringstream &stream,
                             unsigned index_in_permutation,
                             std::function<double(unsigned)> rank);

  void print_summary(const std::string &description,
                     std::function<double(unsigned)> rank);

  string_variable *Labels;
  counter_variable *Success;
  counter_variable *Failure;

  unsigned NumColumns;
  std::vector<std::string> Rows;
  std::vector<unsigned> Permutation; // scratch variable

  const unsigned ColumnWidth = 30;
  const unsigned ColumnSpacing = 2;
  const unsigned NumTopElements = 10;
};

void success_rate_variable::accumulate() {
  Labels->accumulate();
  Success->accumulate();
  Failure->accumulate();
}

void success_rate_variable::print_label_with_rank(
    std::ostringstream &stream, unsigned index_in_permutation, std::function<double(unsigned)> rank) {
  unsigned index = Permutation[index_in_permutation];
  Labels->print_scalar(stream, index);

  stream << " (" << std::setprecision(2) << std::fixed << rank(index) << ")";
}

void success_rate_variable::print_summary(
    const std::string &description,
    std::function<double(unsigned)> rank) {
  unsigned size = Labels->num_elements_real();
  NumColumns += 1;

  Permutation.resize(size);
  for (unsigned i = 0; i < size; ++i)
    Permutation[i] = i;

  std::sort(
      Permutation.begin(), Permutation.end(),
      [rank](unsigned a, unsigned b) {
        double ra = rank(a);
        double rb = rank(b);
        if (std::isnan(ra))
          ra = -1;
        if (std::isnan(rb))
          rb = -1;
        return ra < rb;
      });

  unsigned row_index = 0;
  auto append_to_next_row = [&](const std::string &text) {
    assert(row_index < Rows.size());
    auto &row = Rows[row_index++];
    row.append(text);
    unsigned expected_size = NumColumns * ColumnWidth;
    if (row.size() < expected_size)
      row.append(expected_size - row.size(), ' ');
    row.append(ColumnSpacing, ' ');
  };

  append_to_next_row(description);
  append_to_next_row("");

  if (size <= 2 * NumTopElements) {
    for (unsigned i = 0; i < size; ++i) {
      std::ostringstream out;
      print_label_with_rank(out, i, rank);
      append_to_next_row(out.str());
    }
  } else {
    for (unsigned i = 0; i < NumTopElements; ++i) {
      std::ostringstream out;
      print_label_with_rank(out, i, rank);
      append_to_next_row(out.str());
    }
    append_to_next_row("");
    append_to_next_row("...");
    append_to_next_row("");
    for (unsigned i = size - NumTopElements; i < size; ++i) {
      std::ostringstream out;
      print_label_with_rank(out, i, rank);
      append_to_next_row(out.str());
    }
  }

  assert(row_index == Rows.size());
}

void success_rate_variable::print(FILE *stream, unsigned var_index) {
  unsigned size = Labels->num_elements_real();
  bool with_ellipsis = size > 2 * NumTopElements;

  NumColumns = 0;
  Rows.resize(with_ellipsis ? (5 + 2 * NumTopElements) : (2 + size));
  for (auto &row : Rows)
    row.clear();

  auto total = [this](unsigned i) {
    return 0.0 + Success->get(i) + Failure->get(i);
  };
  auto total_acc = [this](unsigned i) {
    return 0.0 + Success->get_accumulated(i) + Failure->get_accumulated(i);
  };
  auto percent = [this, total](unsigned i) {
    return Success->get(i) / total(i);
  };
  auto percent_acc = [this, total_acc](unsigned i) {
    return Success->get_accumulated(i) / total_acc(i);
  };
  print_summary("Usage count (queue)", total_acc);
  print_summary("Usage count (all)", total);
  print_summary("Success (queue)", percent_acc);
  print_summary("Success (all)", percent);
  print_summary("Success (queue-to-all)", [percent_acc, percent](unsigned i) {
    return percent_acc(i) / percent(i);
  });

  fprintf(stderr, "Variable #%u: %s\n\n", var_index, Name.c_str());
  for (auto &row : Rows) {
    while (row.back() == ' ')
      row.pop_back();
    fprintf(stderr, "%s\n", row.c_str());
  }
}

success_rate_variable::~success_rate_variable() {
  delete Labels;
  delete Success;
  delete Failure;
}

bool variable::create_from_shm(std::vector<variable *> &variables,
                               buffer_ref main_area,
                               buffer_ref aux_area,
                               uint8_t **ptr) {
  if (!main_area.contains(*ptr, sizeof(struct mutator_var_header)))
    return false;

  DECL_WITH_TYPE(struct mutator_var_header, header, *ptr);
  unsigned type = header->type;
  unsigned name_bytes = header->name_bytes;
  unsigned bytes_per_element = header->bytes_per_element;
  unsigned max_num_elements = header->max_num_elements;

  // Prevent occasional integer overflows
  if (name_bytes > 1024 ||
      bytes_per_element > 1024 ||
      max_num_elements > 1024)
    return false;

  size_t size = sizeof(*header) + name_bytes + bytes_per_element * max_num_elements;
  if (!main_area.contains(*ptr, size))
    return false;

  const char *name_ptr = (const char *)(*ptr + sizeof(*header));
  std::string name(name_ptr, name_bytes);
  while (!name.empty() && name.back() == '\0')
    name.pop_back();

  uint8_t *payload = *ptr + sizeof(*header) + name_bytes;
  uint8_t *aux_payload = aux_area.bytes() + (payload - main_area.bytes());

  *ptr += size;

  switch (type) {
  case MUTATOR_VAR_COUNTERS:
    if (bytes_per_element != 8) {
      DEBUG("Counter %s: unexpected bytes_per_element = %u.\n",
            name.c_str(), bytes_per_element);
      return false;
    }

    variables.push_back(new counter_variable(
        std::move(name), max_num_elements, &header->num_elements_real,
        (mutator_u64_var_t *)payload,
        (mutator_u64_var_t *)aux_payload));

    return true;
  case MUTATOR_VAR_STRINGS: {
    std::vector<char *> strings;
    strings.reserve(max_num_elements);
    char *str = (char *)payload;
    for (unsigned i = 0; i < max_num_elements; ++i, str += bytes_per_element)
      strings.push_back(str);

    variables.push_back(new string_variable(
        std::move(name), max_num_elements, &header->num_elements_real,
        std::move(strings), bytes_per_element));

    return true;
  }
  case MUTATOR_VAR_STOP:
    return false;
  case MUTATOR_VAR_SUCCESS_RATE: {
    if (variables.size() < 3)
      return false;
    auto failure = variables.back();
    variables.pop_back();
    auto success = variables.back();
    variables.pop_back();
    auto labels = variables.back();
    variables.pop_back();

    variables.push_back(new success_rate_variable(
        std::move(name),
        static_cast<string_variable *>(labels),
        static_cast<counter_variable *>(success),
        static_cast<counter_variable *>(failure)));
    return true;
  }
  default:
    DEBUG("Unknown var record type: 0x%x\n", type);
    return false;
  }
}

unsigned variable::num_elements_real() {
  unsigned num_elements = *NumElementsReal;
  if (num_elements > MaxNumElements) {
    fprintf(stderr, "!!! Too many elements: %u, using only the first %u ones.\n",
            num_elements, MaxNumElements);
    num_elements = MaxNumElements;
  }
  return num_elements;
}

void variable::print(FILE *stream, unsigned var_index) {
  unsigned num_elements = num_elements_real();
  if (num_elements == 1) {
    fprintf(stream, "Variable #%u:\t", var_index);
    std::ostringstream line;
    print_scalar(line, 0);
    line << "\t - " << Name;
    fprintf(stream, "%s\n", line.str().c_str());
  } else {
    fprintf(stream, "Variable #%u: %s\n", var_index, Name.c_str());
    for (unsigned i = 0; i < num_elements; ++i) {
      std::ostringstream line;
      line << " - [" << i << "]\t";
      print_scalar(line, i);
      fprintf(stream, "%s\n", line.str().c_str());
    }
  }
}

} // namespace mutator
} // namespace kbdysch
