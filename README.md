# CTF Writeups
 
A collection of writeups from various CTF platforms and challenges — reconnaissance, exploitation, and privilege escalation, documented end to end.
 
Each writeup follows a consistent structure: **Reconnaissance → Enumeration → Foothold → User Flag → Privilege Escalation → Root Flag**, followed by a short attack-chain summary and remediation notes. Format varies slightly for non-boot2root challenges (web, crypto, forensics, etc.), where the structure adapts to **Challenge Overview → Analysis → Exploitation → Flag**.
 
## Repository structure
 
```
.
├── README.md
├── HTB/            ← Hack The Box machines
├── RootMe/         ← Root Me machines
```
 
Each platform folder has its own `README.md` indexing its writeups in a table, with links to the full writeup and a short list of key techniques used.
 
## Platforms
 
| Platform | Description | Index |
|---|---|---|
| [Hack The Box](HTB/) | Boot2root machines, full chain to root | [HTB/README.md](HTB/README.md) |
| [Root Me(RootMe/) | Boot2root machines, full chain to root | [RootMe/README.md](RootMe/README.md) |
 
## Writeup format
 
Most writeups follow this skeleton so techniques stay easy to scan and compare across challenges:
 
1. **Reconnaissance** — port/service enumeration, initial fingerprinting
2. **Enumeration** — application analysis, exposed endpoints, version checks
3. **Exploitation / Foothold** — the path to initial access or to solving the challenge
4. **Privilege Escalation** *(boot2root only)* — the full chain to the highest privilege level
5. **Flag(s)**
 
All writeups document activity performed exclusively against the respective platforms' own lab infrastructure, under each platform's terms of service. Credentials, tokens, IPs, and flags shown are specific to ephemeral lab instances and hold no value outside that context.
 
## License
 
Writeups are shared for educational purposes. Feel free to reference or link back, but please don't republish verbatim without attribution.
