#ifndef WILDFIRE_H_
#define WILDFIRE_H_

// Networking
#include <net/if.h>
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
#include <ifaddrs.h>

// General
#include <iostream>
#include <cstdlib>
#include <csignal>
#include <string>
#include <cstring>
#include <limits>
#include <fstream>
#include <regex>
#include <sstream>
#include <random>




class Wildfire {
public:
  char iface[100];
  static Wildfire *Instance;
  static void RunOnce(void);
  static void Run(void);
  static Wildfire *Init(std::string dst_ip);
  static Wildfire *Init(std::string dst_ip, int dst_port);
  static Wildfire *Init(std::string dst_ip, int dst_port, bool DEBUG);
  static Wildfire *Init(std::string dst_ip, int dst_port, bool DEBUG, bool PROMISC);
  void OpenSocket();
  void CloseSocket();
  void Register(void);
  std::string ListenOnce(void);
  void Send(std::string payload);
  static void End(void);


private:
  bool DEBUG, PROMISC;
  int sockfd;
  struct ifreq *sifreq;
  struct sock_fprog filter;
  unsigned char gateway_mac[ETH_ALEN];
  unsigned char interface_mac[ETH_ALEN];
  uint32_t destination_ip, interface_ip;
  uint16_t dst_port, src_port;

  Wildfire(std::string dst_ip, int port, bool DEBUG, bool PROMISC);
  void SendChunk(std::string payload);
  void SetInterfaceMac();
  void SetGatewayMAC(void);
  void GetMacFromIP(char *ip_addr);
  void GetInterfaceName(char iface[]);
  void Sigint(int signum);
  static std::string GetHostname(void);
  static void StaticSignalHandler(int signum){
        Wildfire::End();
  }
  void CalcIPChecksum(struct iphdr *ip);
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
#endif // WILDFIRE_H_
