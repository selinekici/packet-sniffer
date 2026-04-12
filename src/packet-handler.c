#include "packet-handler.h"
#include <stdio.h>

#include <netinet/if_ether.h>

#include <netinet/ip.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>


//note: static is used to enforce internal linkage, restricting these helper functions to file scope.
static void print_src_mac(struct ether_header* eth);
static void print_dest_mac(const struct ether_header* eth);
static void print_eth_type(const struct ether_header* eth);
static void print_pcap_header(const struct pcap_pkthdr* header);



void packet_handler(const unsigned char* const args, const struct pcap_pkthdr* const header, const unsigned char* const packet) {
    (void) args;

    print_pcap_header(header);

    struct ether_header* eth = (struct ether_header *) packet;

    print_src_mac(eth);
    print_dest_mac(eth);
    print_eth_type(eth);


    if (eth->ether_type == htons(ETHERTYPE_IP)){
        struct ip* ip_header = (struct ip *) (packet + sizeof(struct ether_header));

        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        int ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP){

            struct tcphdr* tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + ip_header_length);

            printf("Protocol: TCP\n");
            printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
        }
        else if (ip_header->ip_p == IPPROTO_UDP){

            struct udphdr* udp_header = (struct udphdr *) (packet + sizeof(struct ether_header) + ip_header_length);

            printf("Protocol: UDP\n");
            printf("Source Port: %u\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %u\n", ntohs(udp_header->uh_dport));
        } else {
            printf("Protocol: UNKNOWN");
        }
    } else {
        printf("Not an IPv4 packet\n");
    }
    printf("-----------------------------\n");
}


static void print_dest_mac(const struct ether_header* eth){

    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4],
           eth->ether_dhost[5]);
}

static void print_src_mac(struct ether_header* eth){

    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4],
           eth->ether_shost[5]);
}
 static void print_eth_type(const struct ether_header* eth){

    printf("Ether Type: 0x%04x\n", ntohs(eth->ether_type));

}

static void print_pcap_header(const struct pcap_pkthdr* header){

    printf("Timestamp: %ld.%08ld\n", header->ts.tv_sec, header->ts.tv_usec);
    printf("Captured Length: %u bytes\n", header->caplen);
    printf("Length: %u bytes\n", header->len);

}
