#include "journal.h"
#include "kbdysch/hashing.h"

#include <algorithm>

namespace kbdysch {
namespace mutator {

static void compute_hash(char *hash_str, const buffer_ref data) {
  kbdysch_compute_hash(hash_str, data.bytes(), data.size());
  hash_str[HASH_CHARS] = '\0';
}

journal_data::journal_data(temp_dir &dir)
    : JournalDir(dir) {}

bool journal_data::load_journal(const buffer_ref input_data) {
  if (!read_journal_from_disk(input_data))
    return false;

  return parse_journal(input_data.size());
}

bool journal_data::read_journal_from_disk(const buffer_ref input_data) {
  char hash_str[HASH_CHARS + 1];
  compute_hash(hash_str, input_data);

  int length = JournalDir.read_file(hash_str, RawLog);

  if (length < 0) {
    memset(RawLog.data(), 0, RawLog.size());
    return false;
  }

  if (length < MUTATOR_MAX_LOG_BYTES) {
    DEBUG("Read only %d bytes of log.", length);
    memset(&RawLog[length], 0, RawLog.size() - length);
  }

  return true;
}

bool journal_data::parse_journal(unsigned input_bytes) {
  unsigned position = 0;
  unsigned record_type;
  const void *payload;

  memset(&DefiningSections, -1, sizeof(DefiningSections));
  Sections.clear();
  References.clear();
  Proposals.clear();

  unsigned current_section = 0;
  unsigned current_section_begin = 0;
  while (find_next_record(position, record_type, payload)) {
    switch (record_type) {
    case MUTATOR_LOG_SET_OFFSET: {
      DECL_WITH_TYPE(struct mutator_log_set_offset, set_offset, payload);
      if (set_offset->offset >= input_bytes) {
        ERR("Section %u: offset %u is too high.\n",
            current_section, set_offset->offset);
        break;
      }
      Sections.push_back({current_section_begin, set_offset->offset});
      current_section_begin = set_offset->offset;
      ++current_section;
      break;
    }
    case MUTATOR_LOG_NEW_RES: {
      DECL_WITH_TYPE(struct mutator_log_new_resource, new_res, payload);
      unsigned kind = new_res->kind;
      unsigned id = new_res->id;
      if (kind >= MUTATOR_MAX_RESOURCE_KINDS ||
          id >= MUTATOR_MAX_RESOURCE_IDS) {
        ERR("Section %u: invalid resource with kind = %u, id = %u.\n",
            current_section, kind, id);
        break;
      }
      DefiningSections[kind][id] = current_section;
      break;
    }
    case MUTATOR_LOG_REF_RES: {
      DECL_WITH_TYPE(struct mutator_log_ref_resource, ref_res, payload);
      unsigned kind = ref_res->kind;
      unsigned id = ref_res->id;
      unsigned offset = ref_res->offset;
      unsigned size = ref_res->id_bytes;
      if (kind >= MUTATOR_MAX_RESOURCE_KINDS ||
          id >= MUTATOR_MAX_RESOURCE_IDS) {
        ERR("Section %u: invalid resource reference with kind = %u, id = %u.\n",
            current_section, kind, id);
        break;
      }
      // Check both offset and offset + size in case of overflow
      if (size > 8 || offset >= input_bytes || offset + size > input_bytes) {
        ERR("Section %u: unexpected resource reference: offset = %u, size = %u.\n",
            current_section, offset, size);
        break;
      }
      References.push_back({*ref_res, current_section,
                            DefiningSections[kind][id]});
      break;
    }
    case MUTATOR_LOG_PROPOSE_CHANGE: {
      DECL_WITH_TYPE(struct mutator_log_propose_change, proposal, payload);
      unsigned offset = proposal->offset;
      unsigned size = proposal->size;
      if (size > 8 || offset + size > input_bytes) {
        ERR("Section %u: unexpected proposal: offset = %u, size = %u.\n",
            current_section, offset, size);
        break;
      }
      Proposals.push_back(*proposal);
      break;
    }
    default:
      break;
    }
  }
  Sections.push_back({current_section_begin, input_bytes});

  return true;
}

bool journal_data::find_next_record(unsigned &opaque_offset, unsigned &record_type, const void *&payload) {
  const uint8_t *ptr = &RawLog[opaque_offset];
  size_t total_bytes = sizeof(struct mutator_log_record_header);
  total_bytes += 16; // FIXME payload size

  if (!buffer_contains(RawLog, ptr, total_bytes)) {
    ERR("Error parsing log, offset %d\n", opaque_offset);
    return false;
  }

  DECL_WITH_TYPE(struct mutator_log_record_header, header, ptr);
  payload = &ptr[sizeof(*header)]; // FIXME check payload in bounds

  opaque_offset += std::max((unsigned)header->size, 1u); // FIXME
  record_type = header->type;
  return header->type != MUTATOR_LOG_STOP;
}

} // namespace mutator
} // namespace kbdysch
