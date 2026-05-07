#include "packet-handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "flow.h"

#define QUEUE_SIZE 100

atomic_int is_stopped = 1;

static char *queue[QUEUE_SIZE];
static int front = 0;
static int rear = 0;
static int count = 0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t not_full = PTHREAD_COND_INITIALIZER;
static pthread_cond_t not_empty = PTHREAD_COND_INITIALIZER;


void producer(char *http_data) {
    pthread_mutex_lock(&mutex);

    while (count == QUEUE_SIZE) {
        pthread_cond_wait(&not_full, &mutex);
    }

    queue[rear] = http_data;
    rear = (rear + 1) % QUEUE_SIZE;
    count++;

    pthread_cond_signal(&not_empty);
    pthread_mutex_unlock(&mutex);
}

void stop_consumer(void) {
    atomic_store(&is_stopped, 0);

    pthread_mutex_lock(&mutex);
    pthread_cond_broadcast(&not_empty);
    pthread_mutex_unlock(&mutex);
}

void *consumer(void *arg) {
    FILE *http_file = (FILE *) arg;

    for (;;) {
        pthread_mutex_lock(&mutex);

        while (count == 0 && atomic_load(&is_stopped)) {
            pthread_cond_wait(&not_empty, &mutex);
        }

        if (count == 0 && !atomic_load(&is_stopped)) {
            pthread_mutex_unlock(&mutex);
            break;
        }

        char *http_data = queue[front];
        front = (front + 1) % QUEUE_SIZE;
        count--;

        pthread_cond_signal(&not_full);
        pthread_mutex_unlock(&mutex);

        fprintf(http_file, "HTTP: %s\n", http_data);
        free(http_data);
    }

    return NULL;
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;


    if (header == NULL || packet == NULL) {
        return;
    }

    if (header->caplen < sizeof(struct ether_header)) {
        return;
    }

    const struct ether_header *eth = (const struct ether_header *) packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        printf("Not an IPv4 packet\n");
        return;
    }

    const struct ip *ip_header = (const struct ip *) (packet + sizeof(struct ether_header));

    int ip_header_length = ip_header->ip_hl * 4;

    if (ip_header_length < 20) {
        return;
    }

    if (header->caplen < sizeof(struct ether_header) + ip_header_length) {
        return;
    }

    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));


    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_header =
                (const struct tcphdr *) (packet + sizeof(struct ether_header) + ip_header_length);

        printf("Protocol: TCP\n");
        printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));

        FiveTuple tuple = {0};
        tuple.src_ip = ip_header->ip_src.s_addr;
        tuple.dst_ip = ip_header->ip_dst.s_addr;
        tuple.src_port = tcp_header->th_sport;
        tuple.dst_port = tcp_header->th_dport;
        tuple.protocol = IPPROTO_TCP;


        int tcp_header_length = tcp_header->th_off * 4;

        if (tcp_header_length < 20) {
            return;
        }

        int ip_total_length = ntohs(ip_header->ip_len);

        if (ip_total_length < ip_header_length + tcp_header_length) {
            return;
        }

        int payload_length = ip_total_length - ip_header_length - tcp_header_length;

        if (payload_length < 0) {
            return;
        }

        process_packet_flow(tuple, payload_length);

        printf("Payload Length: %d bytes\n", payload_length);


        int payload_offset = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
        const char *payload = (const char *) (packet + payload_offset);


        if ((payload_length >= 3 && memcmp(payload, "GET", 3) == 0) ||
            (payload_length >= 4 && memcmp(payload, "POST", 4) == 0)) {
            char *http_buff = malloc(4096);
            if (http_buff == NULL) {
                perror("malloc");
                return;
            }

            http_buff[0] = '\0';

            const char *start = payload;
            const char *end = strstr(start, "\r\n");
            char *buffer_index = http_buff;
            size_t remaining = 4096;

            while (end != NULL) {
                int length = (int) (end - start);
                if (length <= 0) {
                    break;
                }

                int written = snprintf(buffer_index, remaining, "%.*s\n", length, start);
                if (written < 0 || (size_t) written >= remaining) {
                    break;
                }

                buffer_index += written;
                remaining -= (size_t) written;

                start = end + 2;
                end = strstr(start, "\r\n");
            }

            producer(http_buff);
        } else {
            printf("UNKNOWN PAYLOAD\n");
        }

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp_header =
                (const struct udphdr *) (packet + sizeof(struct ether_header) + ip_header_length);

        printf("Protocol: UDP\n");
        printf("Source Port: %u\n", ntohs(udp_header->uh_sport));
        printf("Destination Port: %u\n", ntohs(udp_header->uh_dport));

        FiveTuple tuple = {0};
        tuple.src_ip = ip_header->ip_src.s_addr;
        tuple.dst_ip = ip_header->ip_dst.s_addr;
        tuple.src_port = udp_header->uh_sport;
        tuple.dst_port = udp_header->uh_dport;
        tuple.protocol = IPPROTO_UDP;

        int udp_header_length = sizeof(struct udphdr);

        int ip_total_length = ntohs(ip_header->ip_len);
        int payload_length = ip_total_length - ip_header_length - udp_header_length;

        process_packet_flow(tuple, payload_length);

    } else {
        printf("Protocol: UNKNOWN\n");
    }
}