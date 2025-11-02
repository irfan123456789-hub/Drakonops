---
title: "nfs"
weight: 9
---
| NFS Export Option | Client root UID mapped to | Root Priv Esc Potential |
| --- | --- | --- |
| `root_squash` (default) | nobody (UID 65534) | ❌ No |
| `no_root_squash` | root (UID 0) | ✅ Yes |

&nbsp;

&nbsp;

```
# NFS Enumeration and Exploitation Cheat Sheet

---

## 1. Ports and Services

- **Port 111/tcp** — Portmapper (rpcbind)  
- **Port 2049/tcp** — NFS server

---

## 2. Initial Enumeration

### Nmap NSE Scripts for NFS

```bash  
nmap -p 111,2049 --script=nfs* <target_ip>  
This runs scripts to enumerate NFS services and related info.

List exported NFS shares  
bash  
Copy  
Edit  
showmount -e <target_ip>  
This shows the shares the NFS server exports.

3. Mounting NFS Shares  
bash  
Copy  
Edit  
sudo mount -t nfs <target_ip>:/exported/share /mnt/nfs  
Mount the exported share locally for inspection.
```