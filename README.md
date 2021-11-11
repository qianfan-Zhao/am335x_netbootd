A dhcp & tftp server for am335x network/usb boot
================================================

项目来源于 [rpi_netbootd](https://github.com/yuanjianpeng/rpi_netbootd) , 在此项目的
基础上修改了AM335x的支持. 因USB网卡的可插拔性, 增加了USB插拔检测.

# AM335x 启动

参考TRM 26.1.9.4 EMAC Boot Procedure一节, 通过EMAC启动时, AM335x会首先发送BOOTP,
并且填充 "vender-class-identifier" option 60为固定字符串 "AM335x ROM", 服务端
通过该选项判断是否为AM335x设备, 并且仅对AM335x的BOOTP进行回复. 获取IP地址之后,
AM335x通过TFTP协议下载bootloader并启动.

AM335x USB启动时, 会虚拟成RNDIS网络, 后续的处理与EMAC启动一致. USB vid:pid
为0451:6141

# TFTP

am335x_netbootd工具实现了TFTP协议, 如果你使用的主机中已经运行过tftp客户端, 需要
首先关闭, 之后在启动am335x_netbootd.

	systemctl stop tftpd-hpa

# USB网卡地址

am335x_netbootd通过-c选项指定usb网络的子网地址, 子网掩码固定为255.255.255.0
其中子网地址.1固定为服务器地址, .2 ~ .200用于给设备动态分配.

# 使用方法

```console
$ sudo ./am335x_netbootd 0451:6141  -c 192.168.200.1
New usb device 0451:6141 with network enp0s29u1u5
AM335x d0:39:72:18:ab:4f take ip 192.168.200.3
tftp request read MLO, mode octet
conn closed, 235.29 KiB/s
```