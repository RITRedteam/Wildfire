#ifndef WILDFIRE_H_
#define WILDFIRE_H_


#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdbool.h>

#define UDP_HDR_SIZE 8

#define INET_HDR_LEN 5

#define MAX_DATA_SIZE 1000


/* BPF code generated with tcpdump -dd udp and port 12345
 * used to filter incoming packets at the socket level
 */
struct sock_filter bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00003039 }, //5
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00003039 }, //7
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00003039 }, //15
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00003039 }, //17
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};

/* its a datagram inside a packet inside a frame!
 * gotta be packed though!
 */
struct __attribute__((__packed__)) udpframe {
    struct ethhdr ehdr;
    struct iphdr ip;
    struct udphdr udp;
    unsigned char data[ETH_DATA_LEN - sizeof(struct udphdr) - sizeof(struct iphdr)];
};

void send_status(unsigned char *buf, int code);
void sigint(int signum);
void ip_checksum(struct iphdr *ip);
void udp_checksum(struct iphdr *ip, unsigned short *payload);
#endif
