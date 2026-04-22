#include "flow.h"
#include "uthash.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

typedef struct {
    FiveTuple key;
    int byte_count;
    UT_hash_handle hh;
} FlowEntry;

static FlowEntry *flows = NULL;

static FlowEntry *find_flow(FiveTuple tuple) {
    FlowEntry *entry = NULL;
    HASH_FIND(hh, flows, &tuple, sizeof(FiveTuple), entry);
    return entry;
}

static FlowEntry *create_flow(FiveTuple tuple, int payload_length) {
    FlowEntry *entry = (FlowEntry *)malloc(sizeof(FlowEntry));
    if (entry == NULL) {
        return NULL;
    }

    entry->key = tuple;
    entry->byte_count = payload_length;
    return entry;
}

static void add_flow(FlowEntry *entry) {
    if (entry == NULL) {
        return;
    }

    HASH_ADD(hh, flows, key, sizeof(FiveTuple), entry);
}

static void increment_packet_count(FlowEntry *entry,int payload_length) {
    if (entry == NULL) {
        return;
    }

    entry->byte_count += payload_length;
}

void process_packet_flow(FiveTuple tuple, int payload_length) {
    FlowEntry *entry = find_flow(tuple);

    if (entry != NULL) {
        increment_packet_count(entry, payload_length);
    } else {
        FlowEntry *new_entry = create_flow(tuple, payload_length);
        add_flow(new_entry);
    }
}

void print_flows_to_file(FILE *out) {
    if (out == NULL) {
        return;
    }

    FlowEntry *current, *tmp;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    HASH_ITER(hh, flows, current, tmp) {
        inet_ntop(AF_INET, &current->key.src_ip, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->key.dst_ip, dst_ip_str, INET_ADDRSTRLEN);

        fprintf(out,
                "Flow -> src_ip=%s, dst_ip=%s, src_port=%u, dst_port=%u, protocol=%u, byte_count=%d\n",
                src_ip_str,
                dst_ip_str,
                ntohs(current->key.src_port),
                ntohs(current->key.dst_port),
                current->key.protocol,
                current->byte_count);
    }
}

void delete_all_flows(void) {
    FlowEntry *current, *tmp;

    HASH_ITER(hh, flows, current, tmp) {
        HASH_DEL(flows, current);
        free(current);
    }

    flows = NULL;
}