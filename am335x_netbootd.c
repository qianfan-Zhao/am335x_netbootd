/*
 * A dhcp & tftp server tools for am335x network/usb boot
 *
 * History:
 *   Herbert Yuan <yuanjp@hust.edu.cn> 2018/5/27
 *   qianfan Zhao <qianfanguijin@163.com> port to am335x platform.
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <pwd.h>
#include <sys/ioctl.h>

#include "dhcpd.h"
#include "tftpd.h"
#include "netboot_device.h"

static int filter_usb_device(struct usb_device *usb)
{
	struct netboot_device *dev = (struct netboot_device *)usb;

	if (usb->vid == 0x0451 && usb->pid == 0x6141) { /* AM335x ROM */
		snprintf(dev->bootfile, sizeof(dev->bootfile) - 1, "MLO");
		dev->usb_bNumberConfigration = 1;
		dev->usb_bInterfaceNumber = 0;
		return 0;
	} else if (usb->vid == 0x0451 && usb->pid == 0xd022) { /* AM335x SPL */
		snprintf(dev->bootfile, sizeof(dev->bootfile) - 1, "u-boot.img");
		dev->usb_bNumberConfigration = 2;
		dev->usb_bInterfaceNumber = 0;
		return 0;
	}

	return -1;
}

#define MAX_TFTP_CONN 32
static struct tftp_conn conn[MAX_TFTP_CONN];

static struct in_addr client_ip = { 0 };

static void get_next_client_ip(struct in_addr *client)
{
	uint32_t n, c = ntohl(client_ip.s_addr);

	*client = client_ip;

	/* generate the next client ip in range [2, 200] */
	n = (c & 0xff) + 1;
	if (n > 200)
		n = 2;
	c &= 0xffffff00;
	c |= n;
	client_ip.s_addr = htonl(c);
}

static void usage(char *cmd)
{
	fprintf(stderr,
		"%s [interface] [-c rpi_ip] [-C tftproot] [-u username] [-d]\n",
		cmd);
	fprintf(stderr,
		"<interface>, listen on this interface,\n"
		"             and use the ip address of this interface \n"
		"             as the tftp server address\n"
		"             interface can be ethernet such as eth0\n"
		"             will search all supported usb network if\n"
		"             [interface] is not selected\n");
	fprintf(stderr, "-d,          daemon mode\n");
	fprintf(stderr, "-c ip,       allocate this ip to rpi,\n"
			"             if you has dhcp server in your LAN ENV,\n"
			"             you can omit this option\n");
	fprintf(stderr, "-C dir,      change tftp root dir\n");
	fprintf(stderr, "-u user,     change user\n");
	exit(EXIT_FAILURE);
}

static int get_ifhwaddr(char *ifname, unsigned char *mac)
{
	struct ifreq ifr;
	int sock;

	if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
		fprintf(stderr, "ifname is too long\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		fprintf(stderr, "socket() for %s failed: %s\n", __FUNCTION__,
			strerror(errno));
		return -1;
	}

	if (-1 == ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		fprintf(stderr, "ioctl() for %s failed: %s\n", __FUNCTION__,
			strerror(errno));
		close(sock);
		return -1;
	}

	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	close(sock);
	return 0;
}

static int get_set_ifaddr(char *ifname, struct in_addr *ipv4)
{
	struct sockaddr_in sai;
	struct ifreq ifr;
	int sock;

	if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
		fprintf(stderr, "ifname is too long\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		fprintf(stderr, "socket() for %s failed: %s\n", __FUNCTION__,
			strerror(errno));
		return -1;
	}

	if (-1 == ioctl(sock, SIOCGIFADDR, &ifr)) {
		/* the network interface doesn't has an ip address */
		if (!ipv4->s_addr) {
			/* the topper level doesn't set ip address */
			fprintf(stderr, "network %s doesn't has an ip address\n"
					"you can use -c option set one\n",
					ifname);
			close(sock);
			return -1;
		}

		/* set ip address and up interface */
		memset(&sai, 0, sizeof(sai));
		sai.sin_family = AF_INET;
		sai.sin_port = 0;
		sai.sin_addr.s_addr = ipv4->s_addr;
		memcpy((char *)&ifr + offsetof(struct ifreq, ifr_addr), &sai,
			sizeof(struct sockaddr));

		if (-1 == ioctl(sock, SIOCSIFADDR, &ifr)) {
			fprintf(stderr, "ioctl() SIFADDR for %s failed: %s\n",
					ifname, strerror(errno));
			close(sock);
			return -1;
		}

		ioctl(sock, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (-1 == ioctl(sock, SIOCSIFFLAGS, &ifr)) {
			fprintf(stderr, "ioctl() SIFFLAGS for %s failed: %s\n",
					ifname, strerror(errno));
			close(sock);
			return -1;
		}
	} else {
		struct in_addr ip;

		ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
		if ((ntohl(ip.s_addr) ^ ntohl(ipv4->s_addr)) & 0xffffff00) {
			/* inet_ntoa is not thread safe, split the message */
			fprintf(stderr, "-c %s and the ip addr of ",
					inet_ntoa(*ipv4));
			fprintf(stderr, "%s (%s) not in a subgroup\n",
					ifname, inet_ntoa(ip));
			close(sock);
			return -1;
		}

		/* replace ipv4 with the real address */
		*ipv4 = ip;
	}

	close(sock);
	return 0;
}

static int if_param(char *ifname, int *ifindex, uint8_t *mac,
		    struct in_addr *server_ip)
{
	if ((*ifindex = if_nametoindex(ifname)) == 0) {
		fprintf(stderr, "get ifindex failed: %s\n", strerror(errno));
		return -1;
	}

	if (-1 == get_ifhwaddr(ifname, mac))
		return -1;

	if (-1 == get_set_ifaddr(ifname, server_ip))
		return -1;

	return 0;
}

static int network_work(struct netboot_device *dev)
{
	int i, sock_dhcp, sock_tftp, ifindex;
	char *ifname = dev->net_ifname;
	uint8_t *mac = dev->mac;

	if (if_param(ifname, &ifindex, mac, &dev->ip_server) < 0)
		return -1;

	sock_dhcp = dhcp_sock(ifindex);
	if (sock_dhcp < 0)
		return -1;

	sock_tftp = tftp_init(dev->ip_server.s_addr, conn, MAX_TFTP_CONN);
	if (sock_tftp < 0)
		return -1;

	while (1) {
		int ret, maxfd;
		struct timeval tv;
		fd_set rfds;

		FD_ZERO(&rfds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_SET(sock_dhcp, &rfds);
		maxfd = sock_dhcp;

		FD_SET(sock_tftp, &rfds);
		if (sock_tftp > maxfd)
			maxfd = sock_tftp;

		for (i = 0; i < MAX_TFTP_CONN; i++) {
			struct tftp_conn *tftp = &conn[i];

			if (tftp->sock != -1) {
				FD_SET(tftp->sock, &rfds);
				if (tftp->sock > maxfd)
					maxfd = tftp->sock;
			}
		}

		ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "select() failed: %s\n",
					strerror(errno));
				break;
			}
			break;
		} else if (ret == 0) {
			int ts = monotonic_ts();
			for (i = 0; i < MAX_TFTP_CONN; i++) {
				if (conn[i].sock == -1)
					continue;
				process_tftp_timeout(&conn[i], ts);
			}
			continue;
		}

		if (FD_ISSET(sock_dhcp, &rfds)) {
			get_next_client_ip(&dev->ip_client);
			if (process_dhcp(sock_dhcp, dev))
				break;
		}

		for (i = 0; i < MAX_TFTP_CONN; i++) {
			struct tftp_conn *tftp = &conn[i];

			if (tftp->sock != -1 && FD_ISSET(tftp->sock, &rfds)) {
				if (process_tftp_conn(tftp) < 0)
					break;
			}
		}

		if (FD_ISSET(sock_tftp, &rfds)) {
			if (process_tftp_req(sock_tftp, dev->ip_server.s_addr, conn,
					 MAX_TFTP_CONN) < 0)
				break;
		}
	}

	printf("network %s down\n", ifname);

	close(sock_dhcp);
	close(sock_tftp);
	for (i = 0; i < MAX_TFTP_CONN; i++) {
		struct tftp_conn *tftp = &conn[i];

		if (tftp->sock != -1) {
			close(tftp->sock);
			tftp->sock = -1;
			if (tftp->fd > 0) {
				close(tftp->fd);
				tftp->fd = -1;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct netboot_device netboot, *device = &netboot;

	int opt;
	int daemon = 0;
	char *user = NULL;
	int uid = 0;
	char *rootdir = NULL;
	struct passwd *pwd;

	if (argc < 2 || !strcmp("-h", argv[1]))
		usage(argv[0]);

	while ((opt = getopt(argc, argv, "hdc:u:C:")) != -1) {
		switch (opt) {
		case 'd':
			daemon = 1;
			break;
		case 'c':
			if (0 == inet_aton(optarg, &client_ip)) {
				fprintf(stderr, "Invalid rpi ip\n");
				return -1;
			} else {
				uint32_t c = ntohl(client_ip.s_addr), s = c;

				/* the default server ip is .1 */
				s &= 0xffffff00;
				s |= 1;
				device->ip_server.s_addr = htonl(s);

				if ((c & 0xff) == 1) {
					/* fix the client ip to .2 */
					c &= 0xffffff00;
					c |= 2;
					client_ip.s_addr = htonl(c);
				}
			}
			break;
		case 'u':
			user = optarg;
			break;
		case 'C':
			rootdir = optarg;
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (optind < argc) {
		snprintf(device->net_ifname, sizeof(device->net_ifname) - 1,
			"%s", argv[optind]);
		device->is_usb_network = 0;
	} else {
		device->is_usb_network = 1;
	}

	if (rootdir) {
		if (chdir(rootdir) == -1) {
			fprintf(stderr, "change root failed: %s\n",
				strerror(errno));
			return -1;
		}
	}

	if (user) {
		errno = 0;
		pwd = getpwnam(user);
		if (pwd == NULL) {
			fprintf(stderr, "get user uid failed\n");
			return 1;
		}
		if (-1 == setuid(pwd->pw_uid)) {
			fprintf(stderr, "set user failed: %s\n",
				strerror(errno));
			return 1;
		}
	}

	if (daemon) {
		int pid = fork();
		if (pid < 0) {
			fprintf(stderr, "fork failed: %s\n", strerror(errno));
			return 1;
		}

		if (pid > 0) {
			exit(0);
		} else {
			int fd = open("/dev/null", O_RDWR);
			if (fd > 0) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
		}
	}

	while (1) {
		if (device->is_usb_network) {
			struct usb_device *usb = &device->usb;

			if (find_usb_device(usb, filter_usb_device) < 0) {
				usleep(250 * 1000);
				continue;
			}

			/* waiting network ready */
			usleep(500 * 1000);
			if (usb_device_get_netadapter(usb,
						device->usb_bNumberConfigration,
						device->usb_bInterfaceNumber,
						device->net_ifname,
						sizeof(device->net_ifname)) < 0)
				continue;

			printf("New usb device %04x:%04x with network %s\n",
				usb->vid, usb->pid, device->net_ifname);
		}

		network_work(device);

		/* wating sometimes until sysfs usb device is cleanup */
		sleep(device->is_usb_network);

		printf("\n");
	}

	return 0;
}
