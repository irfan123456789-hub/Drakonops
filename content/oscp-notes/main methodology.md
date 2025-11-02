---
title: "main methodology"
weight: 1
---
# **Web applications methodology(don't take brute force lightly)**

- **Goggle google google if u don't understand  use hacktricks for unknow stuff**
- check what web app is running using what web and curl

```
curl -IL http://cube.com/
whatweb http://cube.com/
```

&nbsp;

- check exploit for the version of the web app running - searchsploit and exploit db and github

```
searchsploit apache
searchsploit nginx
```

&nbsp;

- if you find a domain name just write it to the

```
sudo nano /etc/hosts
```

- If nothing till now Fuzz the VHOSTS using ffuf

```
cube111@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

&nbsp;

&nbsp;

- Directory busting using ffuf   try with small.txt and big.txt  check every hit

```
ffuf -w directory-list-2.3-small.txt -u http://192.168.120.108/FUZZ
ffuf -w directory-list-2.3-big.txt -u http://192.168.120.108/FUZZ
```

&nbsp;

- file busting using ffuf check with small.txt and big.txt check every hit

```
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
ffuf -w raft-small-files.txt -u http://192.168.120.108/FUZZ
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u 
ffuf -w raft-big-files.txt -u http://192.168.120.108/FUZZ

```

&nbsp;

- test for functionality click every button on the pages  Hover and check where the url goes

&nbsp;

- check source code  HTML comments

```
<!-- This is an HTML comment -->
```

&nbsp;

&nbsp;

- if u find a login page check cms exploit and try default creds-searchsploit and exploit db and github or reuse credentials if you already have

1.  SQL Injection  try the following payloads for error

| Payload |
| --- |
| `'` |
| `"` |
| `#` |
| `;` |
| `)` |
| `' OR 1=1--` |
| `" OR 1=1--` |
| `' OR 'a'='a` |
| `admin'--` |
| `' OR SLEEP(5)--` |

&nbsp;

&nbsp;

&nbsp;

- Login Bruteforce use hydra or burp suite pitch fork attack

```
 cewl http://192.168.190.79/joomla/administrator/ -d 4 -m 5 -w $PWD/cewl2.txt
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
hydra -l elly -e nsr ftp://192.168.237.148
```

&nbsp;

&nbsp;

- ?path=/var/www  if you find parameterrs try sql injection/LFI/RFI remeber LFI sometimes can list directories dont forget to watch out for the source code because sometimes html doesnt render and the output doesnt get shown on the page
- If you find a page which is listing files or some kind of system stuff happening try OS command injection do parameter fuzzing

1.  LFI ---> try reading config files and ssh keys
2.  RFI
3.  log poisoning
4.  phpwrappers read source code  or RCE
5.  sql injection (Union based)
6.  apart from the url parameters also try stuff on http body parameters
7.  That's one time I have done a DC-9 box on proving grounds in which there were like doing parameter fuzzing consider this don't leave this EMPTY FILE?

&nbsp;

&nbsp;

- Check  for file uploads
- and other stuff in the main notes

```
curl -X POST -F "file=@/home/sinner/Documents/oscp/test.txt" -F filename="/tmp/test.txt" http://192.168.185.249:33414/file-upload
```

- ik u will upload backend specific file but sometimes u have to upload .htaccess file to treat image files as the php files
- watch out for ODT files embed macros inside and upload for windows
- check other ports after uploading there might be  a  link or u might be able to upload  from other  port

&nbsp;

&nbsp;

- After logging in check for
- any user credentials
- exploits
- database creds
- any templates to overwrite with our code
- if  web application allows some king of os command injection or crons
- look out for backups ,extensions,plugins and serach for exploits
- sql injection

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Linux privilege escalation

- keep reusing the credentials from other sources to switch user and also try same username and password
    
- situational awareness
    
- sudo -l
    
- id speacial groups lxd/docker other
    
- Start with credential hunting try to check config files and xml files and ssh keys and passwords grep -r "password" /
    
- Look for `.bak`, `.swp`, `.old` files that reveal creds
    
- check writable dirs
    
    find / -writable -type d 2>/dev/null
    
- **PATH Hijacking / Script Injection**
    
- search /home  and /var/tmp   and /tmp and /opt and  /dev/shm  and  /etc check owner and group ls -al and /etc/passwd open it and bash_history file
    
- suid guid
    
- capabilities
    
- linpeas
    
- cron jobs using pspsy
    
- search for local listening ports on the loopback interface ss -lnt
    
- check  mysql database if 3306 is listening on 127.0.0.1
    
- check what proscesses are running using ps auxw check carefully
    
- check the version of the software for any exploit LPE
    
- Check for linux mail server files
    
- LD_PRELOAD Privilege Escalation
    
- kernel exploits
    
- lsblk searching for any unmounted drives
    

&nbsp;

&nbsp;

# Windows privilege escalation

- situational awareness
- group membership net user cube
- privileges whoami /priv
- credential hunting  -- check root and check every directory

```
findstr /SIM /C:"pass" *.ini *.cfg *.config *.xml
```

- check the program Files and program Files x86 directories  to know what non default software is installed and check for exploit or nay vulnerability for privilege escalation
- PS read line powershell history
- TASKLIST  check running proscesses
- Unquoted Service Path
- check for service binary hijacking with sharpup
- is something running locally netstat -ano|findstr LISTENING   if yes pivot to the attack box kali and scan and attack
- winpeas (check out for any higlighted stuff and checkout for autologon credentials)
- **Dumping and Analyzing Process using procdump**
- **INSTALLATION RIGHTS  
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

ssh using git

git pric esc https://medium.com/@bdsalards/proving-grounds-hunit-intermediate-linux-box-walkthrough-a-journey-to-offensive-security-36081fc196d

&nbsp;

&nbsp;

web dav rce https://www.linkedin.com/pulse/exploiting-webdav-gainrce-arav-budhiraja/
