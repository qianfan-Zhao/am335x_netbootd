/*
 * sysfs usb devices helper.
 * qianfan Zhao
 */

#ifndef USB_H
#define USB_H

#include <stdint.h>

struct usb_device {
	int		busnum;
	int		devnum;
	char		usbpath[32];
	uint16_t	vid;
	uint16_t	pid;
	char		manufacturer[64];
	char		product[64];
	int		bDeviceClass;
	int		bDeviceSubClass;
	int		bDeviceProtocol;
};

int find_usb_device(struct usb_device *usb, uint16_t vid, uint16_t pid);
int usb_device_get_netadapter(struct usb_device *usb, int bInterfaceNum,
			      char *ifname, size_t sz_ifname);
#endif
