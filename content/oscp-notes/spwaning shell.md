---
title: "spwaning shell"
weight: 25
---
&nbsp;sh

```shell-session
/bin/sh -i
sh: no job control in this shell
sh-4.2$
```

&nbsp;

perl

```shell-session
perl —e 'exec "/bin/sh";'
```

ruby

- ```
        ruby -e 'exec "/bin/sh"'
    ```
    

&nbsp;lua

- ```
        lua -e 'os.execute("/bin/sh")'
    ```
    

&nbsp;

awk

```shell-session
awk 'BEGIN {system("/bin/sh")}'
```

&nbsp;

vim

```shell-session
vim -c ':!/bin/sh'
```

&nbsp;

```shell-session
sudo -l
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

&nbsp;

## Working with Laudanum

The Laudanum files can be found in the `/usr/share/laudanum` directory.

ANTAK webshell

&nbsp;