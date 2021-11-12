#ifndef DHCPD_H_
#define DHCPD_H_

#include "netboot_device.h"

int dhcp_sock(int ifindex);
int process_dhcp(int sock, struct netboot_device *dev);

#endif
