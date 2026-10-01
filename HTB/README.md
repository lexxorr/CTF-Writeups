# HTB Writeups
 
Personal collection of writeups for [Hack The Box](https://hackthebox.com) machines — reconnaissance, exploitation, and privilege escalation, documented end to end.
 
Each writeup follows the same structure: **Reconnaissance → Enumeration → Foothold → User Flag → Privilege Escalation → Root Flag**
 
## Machines
 
| Machine | Writeup |
|---|---|
| Cap | [HTB - Cap.md](<HTB - Cap.md>) |
| Cohort |  [HTB - Cohort.md](<HTB - Cohort.md>) |
| Connected |  [HTB - Connected.md](<HTB - Connected.md>) |
| DevHub |  [HTB - DevHub.md](<HTB - DevHub.md>) |
| Enigma | [HTB - Enigma.md](<HTB - Enigma.md>) |
| Fireflow | [HTB - Fireflow.md](<HTB - Fireflow.md>) |
| Management | [HTB - Management.md](<HTB - Management.md>) |
| Nexus |  [HTB - Nexus.md](<HTB - Nexus.md>) |
| Orion | [HTB - Orion.md](<HTB - Orion.md>) |
| Principal | [HTB - Principal.md](<HTB - Principal.md>) |
| Reactor | [HTB - Reactor.md](<HTB - Reactor.md>) |
| Silentium |  [HTB - Silentium.md](<HTB - Silentium.md>) |
| TwoMillion |  [HTB - TwoMillion.md](<HTB - TwoMillion.md>) |
| Paperwork |  [HTB - Paperwork.md](<HTB - Paperwork.md>) |
 

 
## Structure
 
```
HTB/
├── README.md                  ← this file
├── HTB - <Machine>.md         ← one writeup per machine
```
 
## Writeup format
 
Every writeup follows a consistent skeleton so techniques stay easy to scan and compare across machines:
 
1. **Reconnaissance** — port/service enumeration (Nmap, vhost discovery)
2. **Enumeration** — application fingerprinting, exposed endpoints, version checks
3. **Foothold** — initial exploitation path to a low-privilege shell
4. **User Flag**
5. **Privilege Escalation** — the full chain to root, including any dead ends worth noting
6. **Root Flag**
 
All writeups document activity performed exclusively against Hack The Box's own lab infrastructure, under HTB's terms of service. Credentials, tokens, IPs, and flags shown are specific to ephemeral lab instances and hold no value outside that context.
 
## License
 
Writeups are shared for educational purposes. Feel free to reference or link back, but please don't republish verbatim without attribution.
 
