#include <stdio.h>
#include <pthread.h>
#include <pcap.h>

#include "packet-handler.h"
#include "flow.h"

int main(int argc, char *argv[]) {
    char err_buf[PCAP_ERRBUF_SIZE];

    if (argc < 3) {
        printf("Usage: %s <pcap_file> <out_file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *out_file = argv[2];

    FILE *http_file = fopen(out_file, "w");
    if (http_file == NULL) {
        printf("Could not open output file.\n");
        return 1;
    }

    FILE *flow_file = fopen("flows.txt", "w");
    if (flow_file == NULL) {
        printf("Could not open flow output file.\n");
        fclose(http_file);
        return 1;
    }

    pcap_t *handle = pcap_open_offline(filename, err_buf);

    if (handle == NULL) {
        printf("Could not open pcap file: %s\n", err_buf);
        fclose(http_file);
        fclose(flow_file);
        return 1;
    }

    pthread_t t2;
    if (pthread_create(&t2, NULL, consumer, http_file) != 0) {
        printf("Could not create consumer thread.\n");
        pcap_close(handle);
        fclose(http_file);
        fclose(flow_file);
        return 1;
    }

    int result = pcap_loop(handle, 0, packet_handler, NULL);
    if (result < 0) {
        printf("Error reading packets: %s\n", pcap_geterr(handle));
    }

    stop_consumer();
    pthread_join(t2, NULL);

    print_flows_to_file(flow_file);
    delete_all_flows();

    pcap_close(handle);
    fclose(http_file);
    fclose(flow_file);

    return (result < 0) ? 1 : 0;
}