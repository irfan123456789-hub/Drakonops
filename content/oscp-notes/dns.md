---
title: "dns"
weight: 7
---
| Step | Tool(s) | Notes |
| --- | --- | --- |
| Authenticated DNS dump | `adidnsdump` | Needs creds |
| Zone transfer attempt | `dig axfr` | Often blocked, but worth checking |
| Subdomain brute forcing | `dnsenum`, `ffuf`, `gobuster` | Helps discover hosts/services |
| SRV records enumeration | `dig` | Critical in AD to find services |

## Enumerating DNS Records(Active directory)

#### Using adidnsdump

Miscellaenous Misconfigurations

```shell-session
cube111@local[/local]$ adidnsdump -u inlanefreight\forend ldap://172.16.5.5 

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
```

&nbsp;

&nbsp;

#### Using the -r Option to Resolve Unknown Records

Miscellaenous Misconfigurations

```shell-session
cube111@local[/local]$ adidnsdump -u inlanefreight\forend ldap://172.16.5.5 -r

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

DNS

```shell-session
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

#### Zone Files

DNS

```shell-session
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```

&nbsp;

```shell-session
dig ns inlanefreight.local @10.129.14.128
```

```shell-session
dig ns inlanefreight.local @10.129.14.128
```

```shell-session
dig any inlanefreight.local @10.129.14.128
```

`Asynchronous Full Transfer Zone` (`AXFR`).

```shell-session
dig axfr inlanefreight.local @10.129.14.128
```

```shell-session
dig axfr internal.inlanefreight.local @10.129.14.128
```

```shell-session
dig axfr internal.inlanefreight.local @10.129.14.128
```

```shell-session
fierce --domain zonetransfer.me
```

sub domain bruteforce

```shell-session
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.local @10.129.14.128 | grep -v ';|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

```shell-session
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.local
```

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```

```shell-session
cube111@local[/local]# ./subfinder -d inlanefreight.com -v
```

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/


        /&#x27;___\  /&#x27;___\           /&#x27;___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.inlanefreight.com/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www

<...SNIP...>
```

#### Subbrute

Attacking DNS

```shell-session
cube111@local[/local]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cube111@local[/local]$ cd subbrute
cube111@local[/local]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
cube111@local[/local]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```

&nbsp;

gobuster dns -d dev.inlanefreight.local -w fierce-hostlist.txt -r 10.129.124.236

things learnt:  dont forget to bruteforce the subdomains for furthur subdomains and also the dns zone transfers

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

|     |     |
| --- | --- |
| `dig domain.com SOA` | Retrieves the start of authority (SOA) record for the domain. |
| `dig @1.1.1.1 domain.com` | Specifies a specific name server to query; in this case 1.1.1.1 |
| `dig +trace domain.com` | Shows the full path of DNS resolution. |
| `dig -x 192.168.1.1` | Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server. |
| `dig +short domain.com` | Provides a short, concise answer to the query. |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output. |
| `dig domain.com ANY` | Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)). |

&nbsp;

&nbsp;

&nbsp;

DOMAIN take over

https://github.com/EdOverflow/can-i-take-over-xyz

The tool has found four subdomains associated with `inlanefreight.com`. Using the `nslookup` or `host` command, we can enumerate the `CNAME` records for those subdomains.

Attacking DNS

```shell-session
cube111@local[/local]# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

DNS POISONING

#### Local DNS Cache Poisoning

From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

Attacking DNS

```shell-session
cube111@local[/local]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

![](/resources/target.png)

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`:

![](/resources/etter_plug.png)

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`:

![](/resources/etter_site.png)

In addition, a ping coming from the target IP address `192.168.152.129` to `inlanefreight.com` should be resolved to `192.168.225.110` as well:

Attacking DNS

```cmd-session
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.225.110:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

These are a few examples of common DNS attacks. There are other more advanced attacks that will be covered in later modules.
