all:
	$(CC) -o pinetbootd pinetbootd.c dhcpd.c tftpd.c usb_linux.c

clean:	
	rm -fr pinetbootd



