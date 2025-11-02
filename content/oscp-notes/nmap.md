---
title: "nmap"
weight: 5
---

- Normal output (`-oN`) with the `.nmap` file extension
- Grepable output (`-oG`) with the `.gnmap` file extension
- XML output (`-oX`) with the `.xml` file extension
-  convert to html
    
    ```shell-session
    cube111@local[/local]$ xsltproc target.xml -o target.html
    ```
    

&nbsp;   

&nbsp;

```shell-session
cube111@local[/local]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:08 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up (0.023s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

| **Scanning Options** | **Description** |
| --- | --- |
| `10.129.2.18` | Performs defined scans against the target. |
| `-sn` | Disables port scanning. |
| `-oA host` | Stores the results in all formats starting with the name 'host'. |
| `-PE` | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--packet-trace` | Shows all packets sent and received |

* * *

Another way to determine why Nmap has our target marked as "alive" is with the "`--reason`" option.

Host Discovery

```shell-session
cube111@local[/local]$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:10 CEST
SENT (0.0074s) ARP who-has 10.129.2.18 tell 10.10.14.2
RCVD (0.0309s) ARP reply 10.129.2.18 is-at DE:AD:00:00:BE:EF
Nmap scan report for 10.129.2.18
Host is up, received arp-response (0.028s latency).
MAC Address: DE:AD:00:00:BE:EF
Nmap done: 1 IP address (1 host up) scanned in 0.03 seconds
```

scanning hosts in a file 

```shell-session
cube111@local[/local]$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5

10.129.2.18
10.129.2.19
10.129.2.20
```

IDS evasions

```
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace

```

`sudo nmap 192.168.0.0.1 -sA -n -Pn --disable-arp-ping --packet-trace`

decoy scan

```shell-session
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

Source ip change

&nbsp;

```shell-session
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

```shell-session
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

os

```shell-session
sudo nmap 10.129.2.28 -n -Pn -p445 -O
```

&nbsp;

DNS proxy scan

```shell-session
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

DNs proxy connect

```shell-session
ncat -nv --source-port 53 10.129.2.28 50000
```

&nbsp;