# HTB Writeups

Personal collection of writeups for [Hack The Box](https://www.hackthebox.com/) machines — reconnaissance, exploitation, and privilege escalation, documented end to end.

Each writeup follows the same structure: **Reconnaissance → Enumeration → Foothold → User Flag → Privilege Escalation → Root Flag**

## Machines

| Machine | Writeup |
|---------|---------|
| Cap | [Cap.md](Cap.md) |
| Cohort | [Cohort.md](Cohort.md) |
| Connected | [Connected.md](Connected.md) |
| DevHub | [DevHub.md](DevHub.md) |
| Enigma | [Enigma.md](Enigma.md) |
| Fireflow | [Fireflow.md](Fireflow.md) |
| Management | [Management.md](Management.md) |
| Nexus | [Nexus.md](Nexus.md) |
| Orion | [Orion.md](Orion.md) |
| Principal | [Principal.md](Principal.md) |
| Reactor | [Reactor.md](Reactor.md) |
| Silentium | [Silentium.md](Silentium.md) |
| TwoMillion | [TwoMillion.md](TwoMillion.md) |
| Paperwork | [Paperwork.md](Paperwork.md) |
| MakeSense | [MakeSense.md](MakeSense.md) |
| SmartHire | [SmartHire.md](SmartHire.md) |

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
