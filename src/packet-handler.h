#ifndef PACKET_SNIFFER_PACKET_HANDLER_H
#define PACKET_SNIFFER_PACKET_HANDLER_H

#include <pcap.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void producer(char *data);
void *consumer(void *arg);
void stop_consumer(void);

#endif