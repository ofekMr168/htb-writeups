# Usage — HackTheBox, Linux (Easy)

## Summary

Usage is a Linux box that chains three distinct web and system weaknesses into a full compromise. Initial access comes from a **blind SQL injection** in a Laravel password-reset endpoint, used to dump and crack an admin credential. Admin access to a `laravel-admin` panel exposes an **arbitrary file upload** (CVE-2023-24249) that yields code execution. Privilege escalation abuses a `sudo`-granted backup script that runs **7-Zip as root**, whose list-file syntax (`@file`) is turned into an arbitrary-file-read primitive to leak root's SSH private key. The headline lesson: "helpful" features — an ORM query, an avatar uploader, a tool's list-file flag — become vulnerabilities the moment they handle untrusted input without validation or run with elevated privilege.

## Recon & Enumeration

An initial `nmap` service scan showed only two open ports:

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
```

The HTTP service redirected to a virtual host, `usage.htb`, so I added it to `/etc/hosts`. Because the application is vhost-based, I fuzzed for additional subdomains and found an administrative one, `admin.usage.htb`, which I also added to hosts.

The main site exposed a standard login/registration flow plus a **forgot-password** page. Password-reset endpoints are a high-value target: they take user input (an email), look it up in the database, and are often written with less scrutiny than the login form. That made it the first thing to test.

## Foothold / Initial Access

### Confirming the injection

The reset form submits a `POST /forget-password` with an `email` parameter. Testing it in Burp Repeater:

- A normal value returned a clean `302` redirect.
- A single quote (`email=test'`) returned **`HTTP/1.1 500 Internal Server Error`**.

That difference is the whole confirmation. A clean input produces a valid query; a single quote breaks the SQL syntax, and the application throws a 500. **Why it's vulnerable:** the query is built by concatenating user input directly into the SQL string instead of using a parameterized (prepared) statement, so my quote changes the structure of the query rather than being treated as data.

Manual `SLEEP()` payloads didn't produce a time delay — the exact syntax didn't line up with how the query was constructed — but the 500 already proved the injection existed, so I moved to `sqlmap` to enumerate it reliably.

### Automating with sqlmap

The back-end is Laravel over MySQL. A first `sqlmap` run failed with a warning that the request file still contained my manual payload — sqlmap needs the parameter at a clean baseline value so it can inject its own tests. After resetting `email` to a plain value, sqlmap confirmed two injection types:

```
Type: boolean-based blind — AND boolean-based blind (WHERE/HAVING, subquery - comment)
Type: time-based blind   — MySQL > 5.0.12 AND time-based blind (heavy query)
back-end DBMS: MySQL >= 8.0.0
```

A detail worth understanding: my manual `SLEEP()` failed, but sqlmap's time-based technique worked because it used a **heavy query** — a deliberately expensive `COUNT(*)` across cross-joined `INFORMATION_SCHEMA.COLUMNS` tables — rather than the `SLEEP()` function. Same principle (induce a measurable delay to infer a bit), different mechanism.

**Why blind injection is slow:** neither technique returns data directly in the response (there's no UNION or error-based output). Instead, each character of each value is inferred one bit at a time through true/false questions ("is the first character between a–m? yes/no…"). Every bit costs HTTP round-trips, so extraction is inherently slow. I sped it up with `--technique=B` (dropping the slower time-based method) and `--threads=10`.

Enumerating the application database `usage_blog` gave 15 tables, including `admin_users`. The first dump returned a corrupted password field — sqlmap warned about a binary field, and under high thread count against an unstable server, some bits were read incorrectly. Re-running the dump of just the `password` column with `--threads=1 --fresh-queries` (prioritising read accuracy over speed) returned the clean hash:

```
admin : $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
```

The `$2y$10$` prefix identifies it as **bcrypt** (work factor 10). Cracking with hashcat mode 3200 against `rockyou.txt` recovered the password quickly because it was an early dictionary word:

```
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
→ whatever1
```

bcrypt is deliberately slow to brute-force; a stronger password would have required a GPU or a targeted wordlist.

### Code execution via file upload

Logging into `admin.usage.htb` with `admin:whatever1` landed an **Administrator** session. The dashboard disclosed the component stack, including:

```
encore/laravel-admin   1.8.18
```

This version is vulnerable to **[CVE-2023-24249](https://nvd.nist.gov/vuln/detail/CVE-2023-24249)** — arbitrary file upload through the profile avatar field. **Why it's exploitable:** the uploader validates the file type on the client side only; server-side it saves the file without properly restricting dangerous extensions, and since the stack runs PHP via `php-fpm`, an uploaded `.php` file gets executed as code.

The non-obvious part — and the one most worth documenting — was **placement logic**. A first attempt landed the file as `shell.php.png`, which the server treated as an image (trailing `.png`) and refused to execute. The fix was to control the stored filename: uploading through Burp and setting the multipart `filename="shell.php"` (while keeping `Content-Type: image/png` to pass the MIME check) produced a file the server would actually run. Browsing to the uploaded path under `/uploads/` with a `cmd` parameter gave command execution, which I used to drop into an interactive shell.

From there I reached a shell as a low-privileged web user and then a login shell as **`dash`**, whose home directory held the user flag:

```
dash@usage:~$ cat user.txt
61539a3e3866007e66eb8cf8d35205dc
```

## Privilege Escalation

`dash` could not use `sudo`, signalling the path ran elsewhere. Enumerating dash's home directory revealed a **monit** configuration file, `~/.monitrc`, readable as `dash`, which stored a plaintext credential for monit's web interface:

```
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd
```

The box had a second user, `xander`, and that same password worked for `su xander` — a plaintext secret in a service config, reused for a system account. **Why this matters:** config files for monitoring and management daemons are a frequently-overlooked credential store; monit keeps its web-UI password in cleartext by design, and here it doubled as a user password. With `xander`, the `sudo` rights were the key:

```
User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

Running `usage_management` presented a menu; option 1 ("Project Backup") invoked **7-Zip as root** to archive `/var/www/html/*`. Testing the boundary confirmed the restriction was tight — `sudo cat` was explicitly denied — so the escalation had to come through the backup tool itself, not a direct root read.

**The mechanism:** 7-Zip treats an argument of the form `@filename` as a **list file** — a file whose contents are a list of paths to include in the archive. If one of those listed paths is a symlink pointing to a file the current (root) process can read but that I normally cannot, 7-Zip tries to read it as root; when it fails to add it cleanly, it prints the file's contents inside its error/warning output. That turns a backup feature into an arbitrary file read running as root.

Exploitation requires two files in the backed-up directory, created in the right order before running the tool:

1. A symlink named `id_rsa` pointing at the target: `/root/.ssh/id_rsa`.
2. A list file named `@id_rsa` whose contents are the line `id_rsa`.

With both in place, running the backup caused 7-Zip to follow the symlink as root and leak root's private key in its output:

```
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

A practical note: the key as printed to the terminal was unreliable to copy, because text interleaved from 7-Zip's warnings corrupted some base64 characters. Capturing the tool's output to a file and transferring it off the host (rather than copy-pasting from the screen) produced a clean, valid key. With correct `600` permissions, it authenticated directly as root:

```
ssh -i root_key root@usage.htb
root@usage:~# cat root.txt
2aa9f0e68b9d0337011b74bd6e26d799
```

## Key Takeaways

- **A 500 error is a positive signal.** The jump from a clean `302` to a `500 Internal Server Error` on a single quote was the entire injection confirmation — proof that input was reaching the SQL parser unparameterized. Recognising that difference is faster than reaching for a scanner first.
- **Know *why* a tool's technique works.** sqlmap's heavy-query time-based method and the blind bit-by-bit extraction model explain both how the data came out and why it was slow — and why `--threads=1 --fresh-queries` fixed the corrupted read. That reasoning is more valuable in an interview than the command itself.
- **File upload is about placement, not just bypass.** Getting the file accepted is half the job; knowing where it lands and ensuring the server will execute it (`shell.php`, not `shell.php.png`) is the other half.
- **Elevated trust turns benign features into primitives.** 7-Zip's `@` list-file syntax is harmless on its own; combined with `sudo` and a symlink it becomes a root file-read. Always ask what *extra* capability a tool gains when it runs as root.
