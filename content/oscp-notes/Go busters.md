---
title: "Go busters"
weight: 6
---
* * *

Go busters


gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt


### **seclist**
```shell-session
git clone https://github.com/danielmiessler/SecLists
```

### subdomain enumeration
Next, add a DNS Server such as 1.1.1.1 to the `/etc/resolv.conf` file. We will target the domain `inlanefreight.com`, the website for a fictional freight and logistics company.

```shell-session
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```


### Headers
```shell-session
curl -IL https://www.inlanefreight.com
```


### WEB technologies

```shell-session
cube111@local[/local]$ whatweb 10.10.10.121
```

```shell-session
whatweb --no-errors 10.10.10.0/24
```