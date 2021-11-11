all:
	$(CC) -o am335x_netbootd am335x_netbootd.c dhcpd.c tftpd.c usb.c

clean:
	rm -fr am335x_netbootd



