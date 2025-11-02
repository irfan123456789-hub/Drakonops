--- 
title: "footprinting and finger printing web apps"
weight: 4
---
`subdomains`

`curl -s https://crt.sh/json?q=chatgpt.com | jq -r '.[].common_name' | sort -u`

```shell-session
cube111@local[/local]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
cube111@local[/local]$ for i in $(cat ip-addresses.txt);do shodan host $i;done
```

&nbsp;

&nbsp;

```shell-session
dig any inlanefreight.com
```

dig @8.8.8.8 any mjcollege.ac.in\

[domain.glass](https://domain.glass/)

https://buckets.grayhatwarfare.com/

&nbsp;

&nbsp;

&nbsp;

| Tool | Description | Features |
| --- | --- | --- |
| `Wappalyzer` | Browser extension and online service for website technology profiling. | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| `BuiltWith` | Web technology profiler that provides detailed reports on a website's technology stack. | Offers both free and paid plans with varying levels of detail. |
| `WhatWeb` | Command-line tool for website fingerprinting. | Uses a vast database of signatures to identify various web technologies. |
| `Nmap` | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting. |
| `Netcraft` | Offers a range of web security services, including website fingerprinting and security reporting. | Provides detailed reports on a website's technology, hosting provider, and security posture. |
| `wafw00f` | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs). | Helps determine if a WAF is present and, if so, its type and configuration. |

&nbsp;

Header

```shell-session
cube111@local[/local]$ curl -I https://www.inlanefreight.com

HTTP/1.1 200 OK
Date: Fri, 31 May 2024 12:12:26 GMT
Server: Apache/2.4.41 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

&nbsp;

&nbsp;

\*\*\*\*\*VHOSTS

`Web Application Firewalls` (`WAFs`)

```shell-session
cube111@local[/local]$ pip3 install git+https://github.com/EnableSecurity/wafw00f
```

&nbsp;

```shell-session
cube111@local[/local]$ wafw00f inlanefreight.com

                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

                        ~ WAFW00F : v2.2.0 ~
        The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking https://inlanefreight.com
[+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
[~] Number of requests: 2
```

NIKTO

```shell-session
cube111@local[/local]$ sudo apt update && sudo apt install -y perl
cube111@local[/local]$ git clone https://github.com/sullo/nikto
cube111@local[/local]$ cd nikto/program
cube111@local[/local]$ chmod +x ./nikto.pl
```

&nbsp;

```shell-session
nikto -h inlanefreight.com -Tuning b
```

&nbsp;

&nbsp;

check for robots.txt crwlers

check for .well-known end point

gobuster dir -u https://example.com/.well-known/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

&nbsp;

&nbsp;

Web crawling

&nbsp;

```shell-session
cube111@local[/local]$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
cube111@local[/local]$ unzip ReconSpider.zip
```

&nbsp;

```shell-session
cube111@local[/local]$ python3 ReconSpider.py http://inlanefreight.com
```

nano results.json

&nbsp;

&nbsp;

GOOGLE DORKS

| Operator | Operator Description | Example | Example Description |
| :--- | :--- | :--- | :--- |
| `site:` | Limits results to a specific website or domain. | `site:example.com` | Find all publicly accessible pages on example.com. |
| `inurl:` | Finds pages with a specific term in the URL. | `inurl:login` | Search for login pages on any website. |
| `filetype:` | Searches for files of a particular type. | `filetype:pdf` | Find downloadable PDF documents. |
| `intitle:` | Finds pages with a specific term in the title. | `intitle:"confidential report"` | Look for documents titled "confidential report" or similar variations. |
| `intext:` or `inbody:` | Searches for a term within the body text of pages. | `intext:"password reset"` | Identify webpages containing the term “password reset”. |
| `cache:` | Displays the cached version of a webpage (if available). | `cache:example.com` | View the cached version of example.com to see its previous content. |
| `link:` | Finds pages that link to a specific webpage. | `link:example.com` | Identify websites linking to example.com. |
| `related:` | Finds websites related to a specific webpage. | `related:example.com` | Discover websites similar to example.com. |
| `info:` | Provides a summary of information about a webpage. | `info:example.com` | Get basic details about example.com, such as its title and description. |
| `define:` | Provides definitions of a word or phrase. | `define:phishing` | Get a definition of "phishing" from various sources. |
| `numrange:` | Searches for numbers within a specific range. | `site:example.com numrange:1000-2000` | Find pages on example.com containing numbers between 1000 and 2000. |
| `allintext:` | Finds pages containing all specified words in the body text. | `allintext:admin password reset` | Search for pages containing both "admin" and "password reset" in the body text. |
| `allinurl:` | Finds pages containing all specified words in the URL. | `allinurl:admin panel` | Look for pages with "admin" and "panel" in the URL. |
| `allintitle:` | Finds pages containing all specified words in the title. | `allintitle:confidential report 2023` | Search for pages with "confidential," "report," and "2023" in the title. |
| `AND` | Narrows results by requiring all terms to be present. | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com. |
| `OR` | Broadens results by including pages with any of the terms. | `"linux" OR "ubuntu" OR "debian"` | Search for webpages mentioning Linux, Ubuntu, or Debian. |
| `NOT` | Excludes results containing the specified term. | `site:bank.com NOT inurl:login` | Find pages on bank.com excluding login pages. |
| `*` (wildcard) | Represents any character or word. | `site:socialnetwork.com filetype:pdf user* manual` | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search) | Finds results within a specified numerical range. | `site:ecommerce.com "price" 100..500` | Look for products priced between 100 and 500 on an e-commerce website. |
| `" "` (quotation marks) | Searches for exact phrases. | `"information security policy"` | Find documents mentioning the exact phrase "information security policy". |
| `-` (minus sign) | Excludes terms from the search results. | `site:news.com -inurl:sports` | Search for news articles on news.com excluding sports-related content. |

&nbsp;

- `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)

&nbsp;

AUTO RECON

&nbsp;

```shell-session
cube111@local[/local]$ git clone https://github.com/thewhiteh4t/FinalRecon.git
cube111@local[/local]$ cd FinalRecon
cube111@local[/local]$ pip3 install -r requirements.txt
cube111@local[/local]$ chmod +x ./finalrecon.py
cube111@local[/local]$ ./finalrecon.py --help
```

&nbsp;

```shell-session
cube111@local[/local]$ ./finalrecon.py --headers --whois --url http://inlanefreight.com
```

&nbsp;

&nbsp;

&nbsp;
