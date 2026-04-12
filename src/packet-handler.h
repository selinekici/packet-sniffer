#ifndef PACKET_SNIFFER_PACKET_HANDLER_H
#define PACKET_SNIFFER_PACKET_HANDLER_H //buna bak ne ise yariyor>

#include <pcap.h>


/**
 * @brief Captured network packets are processed and analyzed.
 *
 * This function is used as a callback by libpcap. It extracts and prints
 * Ethernet, IP, and TCP/UDP layer information from each packet.
 *
 * @param args   Optional user argument (not used in this implementation)
 * @param header Packet metadata (timestamp, lengths, etc.)
 * @param packet Raw packet data
 */
void packet_handler(const unsigned char* const args, const struct pcap_pkthdr* const header, const unsigned char* const packet);


#endif //PACKET_SNIFFER_PACKET_HANDLER_H
