# Headless — Hack The Box (Easy, Linux)

## Summary

Headless is a web-focused Linux box that chains three classic application flaws into full compromise. A blind stored XSS in a request header is delivered to an administrator through a "hacking attempt" report. That XSS is used to steal the admin's session cookie, which unlocks an admin dashboard. A command injection in the dashboard gives a shell as `dvir`. Root comes from a sudo-allowed script that runs a helper file by **relative path**.

**Headline lesson:** a WAF-style "attack detected" page is itself attack surface, and any header that is later rendered to another user is user input.

---

## Recon & Enumeration

An `nmap -sC -sV` scan showed two open ports:

| Port | Service | Notes |
|---|---|---|
| 22/tcp | OpenSSH 9.2p1 (Debian) | Nothing useful without credentials |
| 5000/tcp | Werkzeug 2.2.2 / Python 3.11.2 | A Flask app, which became the main target |

The site on port 5000 had a "coming soon" page and a `/support` contact form. A session cookie named `is_admin` was set on first visit. Its value had a signed format (`<base64>.<signature>`) and decoded to the string `"user"`.

**Reasoning:** a cookie that literally encodes the role means the role is enforced by the cookie alone. If I could get a *real* admin's cookie, I would become admin. So the question became: is there any way to make an admin's browser execute my code?

---

## Foothold / Initial Access

### 1. Finding the injection point

Sending HTML in the `message` field of the support form triggered a **"Hacking Attempt Detected"** page. The page said the attempt had been reported to the administrators, and it **echoed back the full request headers**, including `User-Agent`, without encoding.

That changes the picture:

- The `message` field is filtered. It is only the *trigger* that generates the report.
- The **headers are not filtered**, and they end up in a report that an admin opens in a browser.

So this is a **blind stored XSS**. The payload goes in the `User-Agent` header, the malicious `message` makes sure a report is created, and the admin bot renders it later.

### 2. Stealing the admin session

The `is_admin` cookie is **not marked `HttpOnly`**, so JavaScript running in the admin's browser can read it. I set up a simple HTTP listener and used a `User-Agent` payload that makes the browser request an image from my listener, with the cookie (Base64-encoded) appended as a query parameter.

**Debugging the chain.** This is where most of the time went. The callback arrived, but the value decoded to the literal string `undefined`. Instead of rewriting the payload blindly, I split the chain into stages:

1. **Is my listener reachable?** Yes. Requests were already arriving from the target IP.
2. **Is the payload executing?** Yes, because something was being sent.
3. **Is the value correct?** No. The expression inside the encoding call was returning `undefined`.

The root cause was a **hidden character introduced by copy-paste** inside the JavaScript expression. Retyping it by hand fixed it, and the next callback carried the admin's cookie.

> Lesson: when an exfil returns garbage, test the JS expression in the browser DevTools console first, and never trust copy-pasted payloads.

### 3. Admin dashboard → Command Injection

With the admin cookie set, `/dashboard` became accessible. It offered a "Generate website health report" form that POSTs a single `date` parameter.

**Reasoning:** a "report" generated from a date often means the backend calls a shell script with that date as an argument. I tested by appending a shell command separator and a harmless command (`id`) to the date. The response included `uid=1000(dvir)`, which confirmed **OS command injection**.

I used this to get a reverse shell as `dvir` and read `user.txt`. A detail that mattered: spaces in the injected value had to be properly URL-encoded, otherwise the command broke.

---

## Privilege Escalation

### Enumeration

The first check as a new user was `sudo -l`. It showed that `dvir` can run `/usr/bin/syscheck` as **root, with no password**.

`syscheck` is a readable bash script. It prints basic system information, then checks whether a database service is running. **If the service is not running, it executes `./initdb.sh`.**

### The mechanism: relative path hijacking

`./initdb.sh` is a **relative path**: it resolves against the *current working directory of whoever runs the script*, not the script's own location. Because I control my working directory, I control which `initdb.sh` gets executed, and it executes **as root** because `syscheck` runs under sudo.

### Exploitation (high level)

1. Moved into a directory where I had write access.
2. Created my own `initdb.sh` (with a `#!/bin/bash` shebang) containing a single privileged action: setting the SUID bit on `/bin/bash`.
3. Made it executable. Without `chmod +x`, `syscheck` simply fails silently.
4. Ran `sudo /usr/bin/syscheck` **from that same directory**.
5. Spawned `bash -p` to keep the elevated privileges. The result was `whoami` → `root`.

Afterwards I removed the SUID bit from `/bin/bash` (cleanup, as I would on a real engagement).

---

## Remediation (how each link should be fixed)

| Finding | Fix |
|---|---|
| Stored XSS via request headers in the report page | Context-aware output encoding of **all** rendered data, including headers. Add a strict Content-Security-Policy. |
| Session/role cookie readable by JavaScript | Set `HttpOnly`, `Secure` and `SameSite` on session cookies. Never store the role client-side; look it up server-side from the session. |
| Command injection in `date` | Never pass user input to a shell. Validate against a strict allowlist (`^\d{4}-\d{2}-\d{2}$`) and call the script with an argument list (no shell). |
| Relative path in a sudo-allowed script | Always use absolute paths (`/opt/app/initdb.sh`) in privileged scripts, and keep sudo rules as narrow as possible. |

---

## Key Takeaways

- **"Attack detected" pages are attack surface.** If a security control logs or reflects the request to a human, every part of that request, especially headers, is an injection point.
- **Debug exploit chains stage by stage**: listener → execution → correct value. It is faster than guessing, and it is exactly how you troubleshoot under exam pressure.
- **Encoding discipline matters.** A missing or double URL-encoding, or a single invisible character, can make a correct payload look broken.
- **The same chain maps directly to real AppSec work**: client-side flaw → session theft → privileged feature → RCE → local privesc. That is a full user → admin → server compromise from one unencoded header.
