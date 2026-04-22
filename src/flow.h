#ifndef FLOW_TRACKER_H
#define FLOW_TRACKER_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t pad[3];
} FiveTuple;

void process_packet_flow(FiveTuple tuple, int payload_length);
void print_flows_to_file(FILE *out);
void delete_all_flows(void);

#endif