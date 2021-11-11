/*
 * sysfs usb devices helper.
 * qianfan Zhao
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "usb.h"

static char *sysfs_attr(const char *dev, const char *attr,
			char *buf, size_t bufsz)
{
	char path[PATH_MAX];
	int fd, len = -1;

	snprintf(path, sizeof(path) - 1, "/sys/bus/usb/devices/%s/%s",
		 dev, attr);

	if ((fd = open(path, O_RDONLY)) >= 0) {
		len = read(fd, buf, bufsz - 1);

		if (len > 0) {
			do {
				buf[len] = '\0';
			} while(--len > 0 && isspace(buf[len]));
		}
		close(fd);
	}

	return (len >= 0) ? buf : NULL;
}

static long sysfs_attr_number(const char *dev, const char *attr, int base,
			       long def)
{
	char *p, buf[128];

	p = sysfs_attr(dev, attr, buf, sizeof(buf));
	if (p && p[0] != '\0')
		return strtol(p, NULL, base);

	return def;
}

#define sysfs_attr_dec(dev, attr, def) sysfs_attr_number(dev, attr, 10, def)
#define sysfs_attr_hex(dev, attr, def) sysfs_attr_number(dev, attr, 16, def)

static char *sysfs_attr_string(const char *dev, const char *attr, char *dst,
			       size_t sz_dst, const char *def)
{
	const char *p;
	char buf[128];

	p = sysfs_attr(dev, attr, buf, sizeof(buf));
	if (!p)
		p = def;

	strncpy(dst, p, sz_dst - 1);
	return dst;
}

static int parse_sys_bus_usb_devices(DIR *dir, struct usb_device *usb)
{
	struct dirent *entry;
	const char *path;

	/* skip ".", "..", "usb1", and usb interfaces like "1-1.4:1.2" */
	do {
		entry= readdir(dir);
		if (!entry)
			return -1;
		path = entry->d_name; /* like 2-1.5 */
	} while (!isdigit(path[0]) || strchr(path, ':'));

	strncpy(usb->usbpath, path, sizeof(usb->usbpath) - 1);
	usb->busnum		= sysfs_attr_dec(path, "busnum", -1);
	usb->devnum		= sysfs_attr_dec(path, "devnum", -1);
	usb->vid		= sysfs_attr_hex(path, "idVendor", 0xffff);
	usb->pid		= sysfs_attr_hex(path, "idProduct", 0xffff);
	usb->bDeviceClass	= sysfs_attr_dec(path, "bDeviceClass", -1);
	usb->bDeviceSubClass	= sysfs_attr_dec(path, "bDeviceSubClass", -1);
	usb->bDeviceProtocol	= sysfs_attr_dec(path, "bDeviceProtocol", -1);

	sysfs_attr_string(path, "manufacturer", usb->manufacturer,
			  sizeof(usb->manufacturer) - 1, "");
	sysfs_attr_string(path, "product", usb->product,
			  sizeof(usb->product) - 1, "");
	return 0;
}

int find_usb_device(struct usb_device *usb, uint16_t vid, uint16_t pid)
{
	DIR *devs = opendir("/sys/bus/usb/devices");
	int found = -1;

	while (devs && !parse_sys_bus_usb_devices(devs, usb)) {
		if (usb->vid == vid && usb->pid == pid) {
			found = 0;
			break;
		}
	}

	closedir(devs);
	return found;
}

static struct dirent *filter_dir(DIR *dir, int (*filter)(struct dirent *))
{
	struct dirent *entry;

	/* find a entry from dir and ignore "." and ".." */
	do {
		entry = readdir(dir);
		if (!entry)
			return NULL;
	} while (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."));

	if (filter(entry) == 0)
		return entry;

	return NULL;
}

static int usb_itfc_match_netadapter(struct dirent *entry)
{
	if (entry) /* match the first netadapter */
		return 0;

	return -1;
}

int usb_device_get_netadapter(struct usb_device *usb, int bInterfaceNum,
			      char *ifname, size_t sz_ifname)
{
	struct dirent *adapter;
	char path[PATH_MAX];
	DIR *dir;

	snprintf(path, sizeof(path) - 1, "/sys/bus/usb/devices/%s/%s:1.%d/net",
		 usb->usbpath, usb->usbpath, bInterfaceNum);

	dir = opendir(path);
	if (!dir)
		return -1;

	adapter = filter_dir(dir, usb_itfc_match_netadapter);
	if (!adapter)
		return -1;

	strncpy(ifname, adapter->d_name, sz_ifname - 1);
	closedir(dir);

	return 0;
}
