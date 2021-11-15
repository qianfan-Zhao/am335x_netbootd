/*
 * netboot device instance
 * qianfan Zhao
 */

#ifndef NETBOOT_DEVICE_H
#define NETBOOT_DEVICE_H

#include "usb.h"

struct netboot_device {
	struct			usb_device usb;

	int			is_usb_network;
	int			usb_bNumberConfigration;
	int			usb_bInterfaceNumber;
	char			net_ifname[32];
	uint8_t			mac[6];
	struct in_addr		ip_client;
	struct in_addr		ip_server;
	char			bootfile[128];
	char			dhcp_vci[64];
};

void netboot_device_generate_client_ip(struct netboot_device *dev);

#endif

