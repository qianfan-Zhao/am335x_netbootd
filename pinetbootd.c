/*
 * Herbert Yuan <yuanjp@hust.edu.cn> 2018/5/27
 * qianfan Zhao <qianfanguijin@163.com> port to am335x platform.
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

#define MAX_TFTP_CONN 32
static struct tftp_conn conn[MAX_TFTP_CONN];

static void usage(char *cmd)
{
	fprintf(stderr,
		"%s <interface> [-c rpi_ip] [-C tftproot] [-u username] [-d]\n",
		cmd);
	fprintf(stderr,
		"<interface>, listen on this interface,\n"
		"             and use the ip address of this interface \n"
		"             as the tftp server address\n"
		"             interface can be ethernet such as eth0\n"
		"             or a usb network selected by vid:pid,\n"
		"             will auto set usb network's ip address based on\n"
		"             -c options, ipv4 address .1 is server ip\n");
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

	printf("hw addr of %s: %02x:%02x:%02x:%02x:%02x:%02x\n", ifname, mac[0],
	       mac[1], mac[2], mac[3], mac[4], mac[5]);
	printf("ip addr of %s: %s\n", ifname, inet_ntoa(*server_ip));
	return 0;
}

int main(int argc, char **argv)
{
	char *ifname = NULL;
	struct in_addr client_ip = { 0 }, server_ip = { 0 };
	unsigned char mac[6];
	int opt;
	int daemon = 0;
	int ifindex;
	int ret;
	char *user = NULL;
	int uid = 0;
	char *rootdir = NULL;
	struct passwd *pwd;
	uint16_t vid = 0xffff, pid = 0xffff;

	int sock_dhcp;
	int sock_tftp;

	int i;
	int maxfd;
	struct timeval tv;
	fd_set rfds;

	if (argc < 2 || !strcmp("-h", argv[1]))
		usage(argv[0]);

	ifname = argv[1];
	optind = 2;
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
				server_ip.s_addr = htonl(s);

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

	if (strchr(ifname, ':')) {
		char *endp = NULL;

		vid = strtoul(ifname, &endp, 16);
		if (!endp || *endp != ':') {
			fprintf(stderr, "invalid usb vid:pid interface\n");
			return -1;
		}

		pid = strtoul(endp + 1, &endp, 16);
		if (!endp || *endp != '\0') {
			fprintf(stderr, "invalid usb vid:pid interface\n");
			return -1;
		}
	}

	if (-1 == if_param(ifname, &ifindex, mac, &server_ip))
		return 1;

	printf("ip addr allocated to rpi: %s\n", inet_ntoa(client_ip));

	if ((sock_dhcp = dhcp_sock(ifindex)) == -1)
		return 1;

	if ((sock_tftp = tftp_init(server_ip.s_addr, conn, MAX_TFTP_CONN)) == -1)
		return 1;

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
		if (pid > 0)
			exit(0);
		else {
			int fd = open("/dev/null", O_RDWR);
			if (fd > 0) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
		}
	}

	while (1) {
		FD_ZERO(&rfds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_SET(sock_dhcp, &rfds);
		maxfd = sock_dhcp;

		FD_SET(sock_tftp, &rfds);
		if (sock_tftp > maxfd)
			maxfd = sock_tftp;

		for (i = 0; i < MAX_TFTP_CONN; i++) {
			if (conn[i].sock != -1) {
				FD_SET(conn[i].sock, &rfds);
				if (conn[i].sock > maxfd)
					maxfd = conn[i].sock;
			}
		}

		ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "select() failed: %s\n",
					strerror(errno));
				break;
			}
			continue;
		}

		else if (ret == 0) {
			int ts = monotonic_ts();
			for (i = 0; i < MAX_TFTP_CONN; i++) {
				if (conn[i].sock == -1)
					continue;
				process_tftp_timeout(&conn[i], ts);
			}
			continue;
		}

		if (FD_ISSET(sock_dhcp, &rfds))
			process_dhcp(sock_dhcp, mac, server_ip.s_addr,
				     client_ip.s_addr);

		for (i = 0; i < MAX_TFTP_CONN; i++) {
			if (conn[i].sock != -1 && FD_ISSET(conn[i].sock, &rfds))
				process_tftp_conn(&conn[i]);
		}

		if (FD_ISSET(sock_tftp, &rfds))
			process_tftp_req(sock_tftp, server_ip.s_addr, conn,
					 MAX_TFTP_CONN);
	}

	return 0;
}
