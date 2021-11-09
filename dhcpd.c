
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>

#include "dhcpd.h"

#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC 0x63825363
#define DHCP_OPTIONS_BUFSIZE 308
#define BOOTREQUEST 1
#define BOOTREPLY 2
#define DHCP_PADDING 0x00
#define DHCP_MESSAGE_TYPE 0x35
#define DHCP_PARAM_REQ 0x37
#define DHCP_MAX_SIZE 0x39
#define DHCP_TFTP_SERVER_NAME 0x42
#define DHCP_TFTP_SERVER_IP 0x36
#define DHCP_VENDOR_CLASS_ID 0x3c
#define DHCP_UUID_CLASS_ID 0x61
#define DHCP_VENDOR_INFO 0x2b
#define DHCP_END 0xff
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define BROADCAST_FLAG 0x8000

#define VENDOR_ID "PXEClient"

struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr_nip;
	uint32_t gateway_nip;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t cookie;
	uint8_t options[DHCP_OPTIONS_BUFSIZE];
} __attribute__((packed));

#define ETH_HDR_LEN sizeof(struct ethhdr)
#define IP_HDR_LEN sizeof(struct iphdr)
#define UDP_HDR_LEN sizeof(struct udphdr)
#define DHCP_LEN sizeof(struct dhcp_packet)

struct dhcp_raw_packet {
	struct ethhdr eth_hdr;
	struct iphdr ip_hdr;
	struct udphdr udp_hdr;
	struct dhcp_packet dhcp_packet;
} __attribute__((packed));

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static unsigned char vendor_info_data[] = {
	0x06, 0x01, 0x03, /* PXE Dsicovery control */
	0x0a, 0x04, 0x00, 0x50, 0x58, 0x45, 0x09, 0x14, 0x00, 0x00,
	0x11, 0x52, 0x61, 0x73, 0x70, 0x62, 0x65, 0x72, 0x72, 0x79,
	0x20, 0x50, 0x69, 0x20, 0x42, 0x6f, 0x6f, 0x74,
};

static uint16_t inet_cksum(uint16_t *addr, int nleft)
{
	/*
     * Our algorithm is simple, using a 32 bit accumulator,
     * we add sequential 16 bit words to it, and at the end, fold
     * back all the carry bits from the top 16 bits into the lower
     * 16 bits.
     */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += *(uint8_t *)addr;
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */

	return (uint16_t)~sum;
}

static int packet_set_filter(int sock, struct sock_filter *filter, int len)
{
	struct sock_fprog fprog;

	fprog.filter = filter;
	fprog.len = len;

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog,
		       sizeof(fprog)) == -1) {
		fprintf(stderr, "setsockopt() SO_ATTACH_FILTER failed: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

static int dhcp_set_filter(int sock)
{
	struct sock_filter dhcp_filter[] = {
		{ 0x28, 0, 0, 0x0000000c },  { 0x15, 0, 22, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },  { 0x15, 0, 20, 0x00000011 },
		{ 0x30, 0, 0, 0x0000000e },  { 0x54, 0, 0, 0x0000000f },
		{ 0x24, 0, 0, 0x00000004 },  { 0x04, 0, 0, 0x0000000e },
		{ 0x02, 0, 0, 0000000000 },  { 0x07, 0, 0, 0000000000 },
		{ 0x48, 0, 0, 0000000000 },  { 0x15, 1, 0, 0x00000043 },
		{ 0x15, 5, 11, 0x00000044 }, { 0x60, 0, 0, 0000000000 },
		{ 0x07, 0, 0, 0000000000 },  { 0x48, 0, 0, 0x00000002 },
		{ 0x15, 6, 0, 0x00000044 },  { 0x06, 0, 0, 0000000000 },
		{ 0x60, 0, 0, 0000000000 },  { 0x07, 0, 0, 0000000000 },
		{ 0x48, 0, 0, 0x00000002 },  { 0x15, 1, 0, 0x00000043 },
		{ 0x06, 0, 0, 0000000000 },  { 0x06, 0, 0, 0xffffffff },
		{ 0x06, 0, 0, 0000000000 },
	};
	return packet_set_filter(sock, dhcp_filter, ARRAY_SIZE(dhcp_filter));
}

static uint8_t *udhcp_get_option(struct dhcp_packet *packet, int code)
{
	uint8_t *optionptr;
	int len;
	int rem;

	/* option bytes: [code][len][data1][data2]..[dataLEN] */
	optionptr = packet->options;
	rem = sizeof(packet->options);
	while (1) {
		if (rem <= 0) {
			fprintf(stderr, "bad packet, malformed option field\n");
			return NULL;
		}

		if (optionptr[OPT_CODE] == DHCP_END)
			break;

		len = 2 + optionptr[OPT_LEN];
		rem -= len;
		if (rem < 0)
			continue; /* complain and return NULL */

		if (optionptr[OPT_CODE] == code) /* Option found */
			return optionptr + OPT_DATA;

		optionptr += len;
	}

	return NULL;
}

static int udhcp_end_option(uint8_t *optionptr)
{
	int i = 0;

	while (optionptr[i] != DHCP_END) {
		if (optionptr[i] != DHCP_PADDING)
			i += optionptr[i + OPT_LEN] + OPT_DATA-1;
		i++;
	}
	return i;
}

static void dhcp_offer_prepare(struct dhcp_raw_packet *raw, uint8_t *src_mac,
			       uint8_t *dst_mac, uint32_t src_ip,
			       uint32_t dst_ip)
{
	struct dhcp_packet *packet = &raw->dhcp_packet;

	memset(raw, 0, sizeof(*raw));

	packet->op = BOOTREPLY;
	packet->htype = 1;
	packet->hlen = 6;
	if (dst_ip) {
		packet->yiaddr = dst_ip;
		packet->siaddr_nip = src_ip;
	}
	packet->cookie = htonl(DHCP_MAGIC);
	memcpy(packet->chaddr, dst_mac, 6);
	packet->options[0] = DHCP_END;

	memcpy(raw->eth_hdr.h_dest, dst_mac, ETH_ALEN);
	memcpy(raw->eth_hdr.h_source, src_mac, ETH_ALEN);
	raw->eth_hdr.h_proto = htons(ETH_P_IP);

	raw->ip_hdr.protocol = IPPROTO_UDP;
	raw->ip_hdr.saddr = src_ip;
	raw->ip_hdr.daddr = INADDR_BROADCAST;

	raw->udp_hdr.source = htons(DHCP_SERVER_PORT);
	raw->udp_hdr.dest = htons(DHCP_CLIENT_PORT);
}

static int dhcp_offer_finish(struct dhcp_raw_packet *raw)
{
	int dhcp_len = offsetof(struct dhcp_packet, options)
			+ udhcp_end_option(raw->dhcp_packet.options);

	if (dhcp_len < 300)
		dhcp_len = 300;

	raw->udp_hdr.len = htons(UDP_HDR_LEN + dhcp_len);
	raw->ip_hdr.tot_len = raw->udp_hdr.len;
	raw->udp_hdr.check = inet_cksum((uint16_t *)&raw->ip_hdr,
					IP_HDR_LEN + UDP_HDR_LEN + dhcp_len);

	raw->ip_hdr.tot_len = htons(IP_HDR_LEN + UDP_HDR_LEN + dhcp_len);
	raw->ip_hdr.ihl = IP_HDR_LEN >> 2;
	raw->ip_hdr.version = IPVERSION;
	raw->ip_hdr.ttl = IPDEFTTL;
	raw->ip_hdr.check = inet_cksum((uint16_t *)&raw->ip_hdr, IP_HDR_LEN);

	return ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + dhcp_len;
}

static struct dhcp_packet *get_dhcp_packet(uint8_t *buf, int buflen, uint8_t *mac)
{
	struct dhcp_raw_packet *packet = (struct dhcp_raw_packet *)buf;
	struct dhcp_packet *dhcp;
	int iplen, udplen;
	uint16_t check;
	uint8_t *opt;

	if (buflen < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)
		return NULL;

	memcpy(mac, packet->eth_hdr.h_source, 6);

	iplen = ntohs(packet->ip_hdr.tot_len);
	udplen = ntohs(packet->udp_hdr.len);

	if (iplen + ETH_HDR_LEN > buflen)
		return NULL;

	if (packet->ip_hdr.protocol != IPPROTO_UDP ||
	    packet->ip_hdr.version != IPVERSION ||
	    packet->ip_hdr.ihl != (IP_HDR_LEN >> 2) ||
	    iplen != IP_HDR_LEN + udplen) {
		fprintf(stderr, "unrelated/bogus packet, ignoring\n");
		return NULL;
	}

	check = packet->ip_hdr.check;
	packet->ip_hdr.check = 0;
	if (check != inet_cksum((uint16_t *)&packet->ip_hdr, IP_HDR_LEN)) {
		fprintf(stderr, "bad IP header checksum, ignoring\n");
		return NULL;
	}

	/* verify UDP checksum. IP header has to be modified for this */
	memset(&packet->ip_hdr, 0, offsetof(struct iphdr, protocol));
	/* ip.xx fields which are not memset: protocol, check, saddr, daddr */
	packet->ip_hdr.tot_len = packet->udp_hdr.len; /* yes, this is needed */
	check = packet->udp_hdr.check;
	packet->udp_hdr.check = 0;
	if (check && check != inet_cksum((uint16_t *)&packet->ip_hdr, iplen)) {
		fprintf(stderr,
			"packet with bad UDP checksum received, ignoring\n");
		return NULL;
	}

	if (packet->udp_hdr.source != htons(DHCP_CLIENT_PORT) ||
	    packet->udp_hdr.dest != htons(DHCP_SERVER_PORT))
		return NULL;

	if (packet->dhcp_packet.cookie != htonl(DHCP_MAGIC)) {
		fprintf(stderr, "packet with bad magic, ignoring\n");
		return NULL;
	}

	dhcp = &packet->dhcp_packet;
	if (dhcp->op != BOOTREQUEST)
		return NULL;

	return dhcp;
}

static void dhcp_options_add_u32(uint8_t **popt, uint8_t code, uint32_t data)
{
	uint8_t *opt = *popt;

	opt[OPT_CODE] = code;
	opt[OPT_LEN] = 4;
	memcpy(&opt[OPT_DATA], &data, 4);
	opt += 6;

	*popt = opt;
	opt[OPT_CODE] = DHCP_END;
}

static int process_am335x_dhcp(struct dhcp_packet *packet, uint8_t *mac,
			       struct dhcp_raw_packet *ack)
{
	struct dhcp_packet *ack_dhcp = &ack->dhcp_packet;
	uint8_t *opt;

	/* "vender-class-identifier" option number 60 (RFC 1497, RFC 1533).
	 * Servers could use this information to identify the device type.
	 * The value present is "AM335x ROM".
	 */
	opt = udhcp_get_option(packet, 60);
	if (!opt || strncmp((char *)opt, "AM335x ROM", 10))
		return -1;

	/* "Client-identifier" option number 61 (RFC 1497, RFC 1533).
	 * This has the ASIC-ID structure which contains additional
	 * info for the device.
	 */
	opt = udhcp_get_option(packet, 61);
	if (!opt)
		return -1;

	printf("New AM335x device: %02x-%02x-%02x-%02x-%02x-%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	ack_dhcp->xid = htonl(1);
	strncpy(ack_dhcp->file, "MLO", sizeof(ack_dhcp->file));

	opt = ack_dhcp->options;
	dhcp_options_add_u32(&opt,  3, ack->ip_hdr.saddr); /* Router */
	dhcp_options_add_u32(&opt, 51, htonl(600)); /* IP Address Lease Time */
	dhcp_options_add_u32(&opt,  1, htonl(0xffffff00)); /* Subnet mask */
	dhcp_options_add_u32(&opt, 54, ack->ip_hdr.saddr); /* DHCP Server */

	return 0;
}

int dhcp_sock(int ifindex)
{
	int sock;
	struct sockaddr_ll sll;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sock == -1) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons(ETH_P_IP);

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	if (dhcp_set_filter(sock)) {
		fprintf(stderr, "set dhcp bpf failed\n");
		close(sock);
		return -1;
	}
	return sock;
}

static struct dhcp_packet *get_dhcp_packet_from_socket(int sock, uint8_t *mac)
{
	static uint8_t buf[1600] = { 0 };
	struct sockaddr_ll sll;
	int ret;

	int addrlen = sizeof(sll);
	ret = recvfrom(sock, buf, sizeof(buf), MSG_TRUNC,
		       (struct sockaddr *)&sll, &addrlen);
	if (ret < 0) {
		if (errno != EINTR)
			fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
		return NULL;
	} else if (ret == 0) {
		fprintf(stderr, "recvfrom ret 0\n");
		return NULL;
	}

	if (sll.sll_pkttype == PACKET_OUTGOING)
		return NULL;

	return get_dhcp_packet(buf, ret, mac);
}

static void handle_dhcp_packet(int sock, struct dhcp_packet *packet,
			       uint8_t *mac, uint8_t *dmac,
			       uint32_t server_ip,
			       uint32_t device_ip)
{
	struct dhcp_raw_packet ack;

	dhcp_offer_prepare(&ack, mac, dmac, server_ip, device_ip);

	if (packet && !process_am335x_dhcp(packet, dmac, &ack)) {
		int len = dhcp_offer_finish(&ack);

		if (sendto(sock, &ack, len, 0, NULL, 0) <= 0) {
			fprintf(stderr, "sendto() failed: %s\n",
				strerror(errno));
		}
	}
}

void process_dhcp(int sock, uint8_t *mac, uint32_t server_ip, uint32_t device_ip)
{
	uint8_t device_macaddr[6] = { 0 };

	handle_dhcp_packet(sock,
			   get_dhcp_packet_from_socket(sock, device_macaddr),
			   mac, device_macaddr,
			   server_ip, device_ip);
}
