# HTB Write-ups

Technical write-ups of HackTheBox machines I've rooted, focused on the *reasoning* behind each step — why a vulnerability exists and why an exploit works — not just the commands.

I'm an offensive security practitioner (OSCP+, PNPT, PJPT) with a red-team and Active Directory focus, building toward a career in penetration testing. These write-ups document my hands-on work in authorized lab environments.

## Machines

| Machine | OS | Difficulty | Status | Key Techniques |
|---------|-----|-----------|--------|----------------|
| [Voleur](./Voleur) | Windows | Medium | ✅ Rooted | Kerberos-only AD (NTLM disabled), Excel hash crack, targeted Kerberoasting (`WriteSPN`), AD Recycle Bin restore, DPAPI credential recovery, WSL/SSH → `NTDS.dit` |
| [Usage](./Usage) | Linux | Easy | ✅ Rooted | Blind SQLi (Laravel), arbitrary file upload (CVE-2023-24249), 7-Zip list-file privesc |
| [SecNotes](./SecNotes) | Windows | Medium | ✅ Rooted | CSRF account takeover, SMB→IIS webshell, WSL bash_history privesc |
| Layover | Linux | Medium | 🔒 Rooted — write-up pending retirement | — |
| Touch | Windows | Easy | 🔒 Rooted — write-up pending retirement | — |

> 🔒 = machine still **active**. Per HackTheBox policy, no solution details are published for active machines; the write-up goes up once the box retires.

## About

- **Certs:** OSCP+, PNPT, PJPT
- **Pro Labs:** Dante, Offshore
- **Focus:** Active Directory, web/application security, red team
- **LinkedIn:** https://www.linkedin.com/in/ofek-mori1285/

> Write-ups here cover **retired** HackTheBox machines only. Active machines are listed as rooted without any solution details until they retire. All work was performed in authorized lab environments — no unauthorized systems were targeted.
