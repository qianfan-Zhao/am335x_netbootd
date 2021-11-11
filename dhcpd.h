#ifndef DHCPD_H_
#define DHCPD_H_

int dhcp_sock(int ifindex);
int process_dhcp(int sock, uint8_t *mac, struct in_addr *s, struct in_addr *c);

#endif
