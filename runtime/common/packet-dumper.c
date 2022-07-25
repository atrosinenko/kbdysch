#include "kbdysch/packet-dumper.h"
#include "kbdysch/logging.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SNAPLEN 1024

enum dump_mode {
  DUMP_RAW_IPV4,
  DUMP_FAKE_UDP,
};

uint8_t IPV4_UDP_HEADER[] = {
  // Start of IPv4
  0x45, 0x00,
  0x00, 0x00, // PATCH: Total Length
  0x00, 0x00, // PATCH: Identification
  0x00, 0x00, 0x40, // Flags, Fragment Offset, TTL
  0x11, // Protocol = UDP
  0x00, 0x00, // Checksum
  0x7f, 0x00, 0x00, 0x01, // PATCH: Source IP
  0x7f, 0x00, 0x00, 0x01, // PATCH: Destination IP
  // Start of UDP
  0x00, 0x00, // PATCH: Source Port
  0x00, 0x00, // PATCH: Destination Port
  0x00, 0x00, // PATCH: Length
  0x00, 0x00, // Checksum
};

#ifdef HAS_LIBPCAP
#include <pcap/pcap.h>
static void do_dump(pcap_dumper_t *d, unsigned counter,
                    void *data, size_t length) {
  struct pcap_pkthdr hdr = {
    .ts = { 0, counter },
    .caplen = length < SNAPLEN ? length : SNAPLEN,
    .len = length,
  };
  pcap_dump((u_char *)d, &hdr, data);
  pcap_dump_flush(d);
}
#else
#define pcap_t void
#define pcap_dumper_t void
#define DLT_IPV4 (-1)
static void do_dump(pcap_dumper_t *d, unsigned counter,
                    void *data, size_t length) {
  abort();
}
#endif

struct packet_dumper {
  pcap_t *pcap;
  pcap_dumper_t *pcap_dumper;
  void *scratch;
  enum dump_mode mode;
  unsigned counter;

  union {
    struct {
      uint16_t port;
    } fake_udp;
  } args;
};

static packet_dumper_t *packet_dumper_open(const char *file_name, enum dump_mode mode, int linktype) {
#ifdef HAS_LIBPCAP
  packet_dumper_t *result = calloc(1, sizeof(*result));

  result->pcap = pcap_open_dead(linktype, SNAPLEN);
  result->pcap_dumper = pcap_dump_open(result->pcap, file_name);
  if (!result->pcap_dumper) {
    LOG_FATAL("Cannot open PCAP log '%s': %s", file_name, pcap_geterr(result->pcap));
    abort();
  }

  result->scratch = malloc(SNAPLEN);
  result->mode = mode;

  return result;
#else
  LOG_FATAL("Packet dumping is not supported.");
  abort();
  return NULL;
#endif
}

packet_dumper_t *open_raw_ipv4_dumper(const char *file_name) {
  return packet_dumper_open(file_name, DUMP_RAW_IPV4, DLT_IPV4);
}

packet_dumper_t *open_fake_udp_dumper(const char *file_name, unsigned port) {
  packet_dumper_t *result = packet_dumper_open(file_name, DUMP_FAKE_UDP, DLT_IPV4);
  result->args.fake_udp.port = port;
  return result;
}

static void dump_raw_ipv4(packet_dumper_t *dumper, void *data, size_t length) {
  do_dump(dumper->pcap_dumper, ++dumper->counter, data, length);
}

static void dump_fake_udp(packet_dumper_t *dumper, void *data, size_t length, bool is_incoming) {
  size_t header_length = sizeof(IPV4_UDP_HEADER);
  uint16_t counter = ++dumper->counter;
  uint16_t port = dumper->args.fake_udp.port;
  memcpy(dumper->scratch, IPV4_UDP_HEADER, header_length);
  *(uint16_t *)(dumper->scratch + 2)   = htons(header_length + length); // Total Length
  *(uint16_t *)(dumper->scratch + 4)   = htons(counter);                // Identification
  *(uint8_t  *)(dumper->scratch + 15) += is_incoming;                   // Source IP
  *(uint8_t  *)(dumper->scratch + 19) += 1 - is_incoming;               // Destination IP
  *(uint16_t *)(dumper->scratch + 20)  = htons(port);                   // Source Port
  *(uint16_t *)(dumper->scratch + 22)  = htons(port);                   // Destination Port
  *(uint16_t *)(dumper->scratch + 24)  = htons(length + 8);             // Length

  size_t payload_caplen = length;
  if (header_length + payload_caplen > SNAPLEN)
    payload_caplen = SNAPLEN - header_length;
  memcpy(dumper->scratch + header_length, data, payload_caplen);

  do_dump(dumper->pcap_dumper, counter, dumper->scratch, header_length + length);
}

void dump_packet(packet_dumper_t *dumper, void *data, size_t length, bool is_incoming) {
  if (!dumper)
    return;

  switch (dumper->mode) {
  case DUMP_RAW_IPV4:
    dump_raw_ipv4(dumper, data, length);
    break;
  case DUMP_FAKE_UDP:
    dump_fake_udp(dumper, data, length, is_incoming);
    break;
  default:
    LOG_FATAL("Unknown mode");
    abort();
  }
}

void packet_dumper_close(packet_dumper_t *dumper) {
  if (!dumper)
    return;

#ifdef HAS_LIBPCAP
  pcap_dump_close(dumper->pcap_dumper);
  pcap_close(dumper->pcap);
  free(dumper->scratch);
#endif
}
