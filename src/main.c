#include <stdio.h>
#include <pcap.h>

#include "packet-handler.h"

int main(int argc, char *argv[]) {
    char err_buf[PCAP_ERRBUF_SIZE];

    // Check if user provided a file name
    if (argc < 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Get file name from command line
    const char *filename = argv[1];


    pcap_t *handle = pcap_open_offline(filename, err_buf);

    if (handle == NULL) {
        printf("Could not open pcap file: %s\n", err_buf);
        return 1;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        printf("Error reading packets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}