## CP450 hard code password for root

### Overview

* Vendor: TOTOLINK

* Product: CP450
* Version: TOTOLINK_C8B193C-1H_CP450_CP0017_8881A_SPI_8M64M_V4.1.0cu.747_B20191224_ALL.web

* Manufacturer's address：https://www.totolink.net/
* Firmware download address ：https://www.totolink.net/data/upload/20200414/2254ce90058da1a549566852c86031db.zip

### Vulnerability details

There is a hard code password for root in /etc/shadow.sample.

![image-20240421163827190](./img/2.png)

The decrypted password is cs2012.

![image-20240421163827190](./img/1.png)
