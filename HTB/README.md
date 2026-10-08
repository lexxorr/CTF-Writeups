# HTB Writeups

Personal collection of writeups for [Hack The Box](https://www.hackthebox.com/) machines — reconnaissance, exploitation, and privilege escalation, documented end to end.

Each writeup follows the same structure: **Reconnaissance → Enumeration → Foothold → User Flag → Privilege Escalation → Root Flag**

## Machines

| Machine | Writeup |
|---------|---------|
| Cap | [Cap.md](easy/Cap.md) |
| Cohort | [Cohort.md](easy/Cohort.md) |
| Connected | [Connected.md](easy/Connected.md) |
| DevHub | [DevHub.md](medium/DevHub.md) |
| Enigma | [Enigma.md](easy/Enigma.md) |
| Fireflow | [Fireflow.md](medium/Fireflow.md) |
| Management | [Management.md](easy/Management.md) |
| Nexus | [Nexus.md](easy/Nexus.md) |
| Orion | [Orion.md](easy/Orion.md) |
| Principal | [Principal.md](medium/Principal.md) |
| Reactor | [Reactor.md](easy/Reactor.md) |
| Silentium | [Silentium.md](easy/Silentium.md) |
| TwoMillion | [TwoMillion.md](easy/TwoMillion.md) |
| Paperwork | [Paperwork.md](easy/Paperwork.md) |
| MakeSense | [MakeSense.md](medium/MakeSense.md) |
| SmartHire | [SmartHire.md](medium/SmartHire.md) |
| Abducted | [Abducted.md](medium/Abducted.md) |
| Bedside | [Bedside.md](medium/Bedside.md) |

## Structure

```
HTB/
├── README.md             ← this file
├── easy/                 ← Easy HTB machines
│   └── <Machine>.md      ← one writeup per machine
└── medium/               ← Medium HTB machines
    └── <Machine>.md      ← one writeup per machine
```

## Writeup format

Every writeup follows a consistent skeleton so techniques stay easy to scan and compare across machines:

- **Reconnaissance** — port/service enumeration (Nmap, vhost discovery)
- **Enumeration** — application fingerprinting, exposed endpoints, version checks
- **Foothold** — initial exploitation path to a low-privilege shell
- **User Flag**
- **Privilege Escalation** — the full chain to root, including any dead ends worth noting
- **Root Flag**

## Disclaimer

All writeups document activity performed exclusively against Hack The Box's own lab infrastructure, under HTB's terms of service. Credentials, tokens, IPs, and flags shown are specific to ephemeral lab instances and hold no value outside that context.

## License

Writeups are shared for educational purposes. Feel free to reference or link back, but please don't republish verbatim without attribution.
