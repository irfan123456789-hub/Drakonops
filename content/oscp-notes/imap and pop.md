---
title: "imap and pop"
weight: 13
---
&nbsp;

&nbsp;

```shell-session
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

&nbsp;

&nbsp;

| **Port** | **Service** |
| --- | --- |
| `TCP/25` | SMTP Unencrypted |
| `TCP/143` | IMAP4 Unencrypted |
| `TCP/110` | POP3 Unencrypted |
| `TCP/465` | SMTP Encrypted |
| `TCP/587` | SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) |
| `TCP/993` | IMAP4 Encrypted |
| `TCP/995` | POP3 Encrypted |

&nbsp;

openssl s_client -connect 142.251.163.109:993 -tls1_2 -crlf

```
openssl s_client -connect 10.129.14.128:imaps
```

```
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
```

curl -k --url 'imaps://142.251.163.109' --user "irfshaik111@gmail.com:vyyi nrpz pjos kqnt"

&nbsp;

#### IMAP Commands

| **Command** | **Description** |
| --- | --- |
| `1 LOGIN username password` | User's login. |
| `1 LIST "" *` | Lists all directories. |
| `1 CREATE "INBOX"` | Creates a mailbox with a specified name. |
| `1 DELETE "INBOX"` | Deletes a mailbox. |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox. |
| `1 LSUB "" *` | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX` | Selects a mailbox so that messages in the mailbox can be accessed. |
| `1 UNSELECT INBOX` | Exits the selected mailbox. |
| `1 FETCH <ID> all` | Retrieves data associated with a message in the mailbox. |
| `1 CLOSE` | Removes all messages with the `Deleted` flag set. |
| `1 LOGOUT` | Closes the connection with the IMAP server. |

\*\*\*\*\*\*\*\*\*A004 UID SEARCH ALL

A3 FETCH 1 BODY\[TEXT\]

&nbsp;

&nbsp;

#### POP3 Commands

```
openssl s_client -connect 10.129.14.128:pop3s
```

| **Command** | **Description** |
| --- | --- |
| `USER username` | Identifies the user. |
| `PASS password` | Authentication of the user using its password. |
| `STAT` | Requests the number of saved emails from the server. |
| `LIST` | Requests from the server the number and size of all emails. |
| `RETR id` | Requests the server to deliver the requested email by ID. |
| `DELE id` | Requests the server to delete the requested email by ID. |
| `CAPA` | Requests the server to display the server capabilities. |
| `RSET` | Requests the server to reset the transmitted information. |
| `QUIT` | Closes the connection with the POP3 server. |

&nbsp;

&nbsp;

#### USER Command

```shell-session
[!bash!]$ telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```

&nbsp;

&nbsp;

&nbsp;

#### Video - Connecting to IMAP and SMTP using Evolution

Click on the image below to see a short video demonstration.

<ins>![Evolution](/resources/ConnectToIMAPandSMTP.jpg)</ins>

&nbsp;

&nbsp;