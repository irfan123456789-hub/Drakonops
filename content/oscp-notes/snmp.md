---
title: "snmp"
weight: 12
---
## Dangerous Settings

Some dangerous settings that the administrator can make with SNMP are:

| **Settings** | **Description** |
| --- | --- |
| `rwuser noauth` | Provides access to the full OID tree without authentication. |
| `rwcommunity <community string> <IPv4 address>` | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6. |

&nbsp;https://secf00tprint.github.io/blog/passwords/crunch/advanced/en

Get the community strings

```shell-session
cube111@local[/local]$ sudo apt install onesixtyone
cube111@local[/local]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

Scanning 1 hosts, 3220 communities
10.129.14.128 [public] Linux local 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
```

&nbsp;

```shell-session
cube111@local[/local]$ sudo apt install braa
cube111@local[/local]$ braa <community string>@<IP>:.1.3.6.*   # Syntax
cube111@local[/local]$ braa public@10.129.14.128:.1.3.6.*

10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux local 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
10.129.14.128:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
10.129.14.128:20ms:.1.3.6.1.2.1.1.3.0:548
10.129.14.128:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.local
10.129.14.128:20ms:.1.3.6.1.2.1.1.5.0:local
10.129.14.128:20ms:.1.3.6.1.2.1.1.6.0:US
10.129.14.128:20ms:.1.3.6.1.2.1.1.7.0:78
```

&nbsp;

&nbsp;

&nbsp;sudo nmap -sU -p161 --script \*snmp\* $target

&nbsp;

snmpwalk -v1 -c public 10.129.220.235 | tee snmp-output.txt    

&nbsp; things learnt :   Review everything carefully from snmpwalk output

&nbsp;