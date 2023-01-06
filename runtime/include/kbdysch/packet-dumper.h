#ifndef KBDYSCH_PACKET_DUMPER_H
#define KBDYSCH_PACKET_DUMPER_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct packet_dumper packet_dumper_t;

packet_dumper_t *open_raw_ipv4_dumper(const char *file_name);
packet_dumper_t *open_fake_udp_dumper(const char *file_name, unsigned port);

void dump_packet(packet_dumper_t *dumper, void *data, size_t length, bool is_incoming);

void packet_dumper_close(packet_dumper_t *dumper);

#ifdef __cplusplus
}
#endif

#endif // KBDYSCH_PACKET_DUMPER_H
