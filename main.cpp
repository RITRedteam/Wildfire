#include "wildfire.h"

int main(int argc, char *argv[]) {
  bool DEBUG = false;
  bool PROMISC = false;
  int dst_port = 53;
  std::string dst_ip("129.21.88.68");

  Wildfire *wildfire = Wildfire::Init(dst_ip, dst_port, DEBUG, PROMISC);
  wildfire->Register();
  wildfire->RunOnce();
  Wildfire::End();
  system("pause");
}
