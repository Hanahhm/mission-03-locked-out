# Mission 3 — "Locked out" · Incident Case File

**Analyst:** Hanah Marroun
**Date:** 2026-10-30
**Environment:** BeCode Hamilton lab
**Target workstation:** `WKS-L62.hamilton.corp` (`10.50.0.62`), seat 62
**Domain controller:** `DC01` (`10.50.0.10`), domain `hamilton.corp`
**Attack machine:** Kali Linux (VirtualBox) reaching the lab over Tailscale

---

## 1. Executive summary (for a manager)

I was locked out of my own workstation and of my security monitoring: both my normal login and my monitoring login had been changed. The workstation was still reachable on the network. By taking inventory of what the machine still exposed, I found a file-sharing service (SMB) open to **anonymous access**. Inside a shared folder, a training account's credentials had been left in a readable text file. That small account was enough to read a domain configuration area (SYSVOL) where an administrative password had been stored in a reversible, publicly-documented format (GPP cpassword). Recovering the password for **my own workstation** gave me back administrative access.

Once back in, I recovered three things left on the desktop: the **proof** of access, the **new monitoring login** (which I rotated immediately), and a **staged set of employee data** the intruder had prepared to steal. That staged data is a **personal-data breach** and triggers notification duties under NIS2 and GDPR (see §7).

**Severity: High.** An attacker obtained administrative access to the workstation and had already staged a set of personal data (employee names, emails and salaries) ready for exfiltration; credentials were also left exposed in several locations. It is not rated Critical because the impact is limited to a single workstation and there is no evidence the data actually left the network. Every weakness used was an avoidable misconfiguration, and each has a cheap fix (see §6).

---

## 2. Timeline (for a technician)

Sentinel times are in UTC (local time zone is UTC+1).

| # | Stage | Action / observation | Evidence |
|---|-------|----------------------|----------|
| 0 | Anonymous access to the share (the open door) | `ANONYMOUS LOGON` (SID `S-1-5-7`), LogonType 3 (Network), NTLM, from `10.50.0.1` | SecurityEvent 4624, ~27-10-2026 15:35 UTC |
| 1 | Recon | Port scan of own workstation | `nmap -p- -sV 10.50.0.62` → 445/tcp SMB (`microsoft-ds`), 3389/tcp RDP (`ms-wbt-server`) |
| 1b | Recon detail | SMB fingerprint | `nmap -sC -sV -p 445,3389 10.50.0.62` → SMB 3.1.1, *"Message signing enabled but not required"* |
| 2 | First foothold | Anonymous (guest) SMB access to the `Public` share | `smbclient //10.50.0.62/Public -N` → `account-access.txt` |
| 2b | Credential in file | File held a temporary training account + flag | user `training01`; flag `HAM{anon_smb_seat62}` |
| 3 | Reach the secret store | Used `training01` to read SYSVOL on the DC | `nxc smb 10.50.0.10 -u training01 -p '***' -M gpp_password` |
| 3b | GPP cpassword | Found a stored password in a per-seat `Groups.xml` | `svc_deploy` ("Legacy deployment account", `RID_ADMIN`), **local** account |
| 3c | Decrypt (my seat) | Reversed the cpassword for **seat62** with Microsoft's **published** AES key | GPO `{824455D7-…}`; flag `HAM{gpp_cpassword_seat62}` |
| 4 | Walk back in | RDP to own workstation with the recovered credential | `xfreerdp3 /v:10.50.0.62 /u:svc_deploy /sec:tls …` → banner `HAM{admin_rdp_seat62}` |
| 4b | Failed logons (lock-out / recovery) | Repeated `svc_deploy` logon failures, then success | SecurityEvent 4625 then 4624, 29-10-2026 ~14:50→15:52 UTC |
| 5 | Proof + loot | Three items on the desktop | `proof_of_access.txt`, `monitoring-access.txt`, `staging\employees.csv` |
| 5b | Rotate | Signed into Sentinel with the recovered login, then changed its password | — |

---

## 3. Technical walkthrough (step by step)

### Step 1 — Reconnaissance
From Kali, over Tailscale:
```bash
nmap -p- -sV 10.50.0.62
```
Only **445/tcp (SMB)** and **3389/tcp (RDP)** open. RDP is the screen service I already knew; the thread to pull is **SMB (445)**.
```bash
nmap -sC -sV -p 445,3389 10.50.0.62
```
Notable: SMB 3.1.1 with *"Message signing enabled but not required"* (a weakness — see §6).

### Step 2 — First foothold (anonymous SMB)
SMB allowed a **guest** session (no credentials):
```bash
smbclient -L 10.50.0.62 -N          # listed shares; "Public" stood out
smbclient //10.50.0.62/Public -N    # entered as guest
smb: \> get account-access.txt
```
`account-access.txt` held a **temporary training account** (`training01`, "to be rotated") and the flag **`HAM{anon_smb_seat62}`**. Credentials must never sit in a readable file on an anonymously-accessible share.

### Step 3 — Finding the real key (GPP cpassword)
`training01` is low-privileged, but any domain account can read **SYSVOL** on the DC, where Group Policy lives:
```bash
nxc smb 10.50.0.10 -u training01 -p '***' -M gpp_password
```
SYSVOL held **one `Groups.xml` per seat**, each with a GPP **`cpassword`** for a local account **`svc_deploy`** (`RID_ADMIN`). The automated tool choked on the base64 (it was **URL-safe**), so I pulled the `Groups.xml` for **my own seat (62)** — GPO `{824455D7-2CBD-4589-A9B3-871AB5BA16C6}` — and decrypted it manually:
- URL-safe base64 → standard (`-`→`+`, `_`→`/`), pad to a multiple of 4
- AES-CBC with the AES key **Microsoft published** in its own documentation (MS14-025)
- decode UTF-16LE, strip PKCS7 padding

This revealed `svc_deploy`'s password **for my workstation**. (Flag for this stage: `HAM{gpp_cpassword_seat62}`.)

**Lesson learned (the useful part):** I first decrypted **another seat's** `Groups.xml` and its password was rejected by my machine. SYSVOL has one per workstation — you must use **your own seat's**. Also, `svc_deploy` is a **local** account, so Kerberos/SAMR password operations against the DC do not apply, and the RDP error `PASSWORD_CERTAINLY_EXPIRED` actually meant *the password I was sending did not match this host* — not that it was expired.

### Step 4 — Walking back in (RDP)
RDP first refused over NLA. The fix was the client's security-mode, not the credential — forcing TLS security:
```bash
xfreerdp3 /v:10.50.0.62 /u:svc_deploy /sec:tls /cert:ignore /dynamic-resolution
```
This landed me on my own desktop as a local administrator. Banner flag: **`HAM{admin_rdp_seat62}`**.

### Step 5 — Proof, monitoring key, and staged data
Three items on the desktop that do not belong:
1. **`proof_of_access.txt`** → flag **`HAM{desktop_proof_seat62}`** (submitted in CTFd — *Proof on the desktop*).
2. **`monitoring-access.txt`** → the new Sentinel login (my BeCode account + a new password). Per the first-reflex rule, I **signed in once and then rotated the password**.
3. **`staging\employees.csv`** → a staged dataset the intruder had prepared to exfiltrate (see §7).

---

## 4. Reconstruction from my own Sentinel (blue)

Workspace `log-sentinel-lab`, table `SecurityEvent`. My workstation's monitoring only records what happens **on my workstation**, so the DC/SYSVOL steps are not here — that is expected.

**a) The anonymous access to my share (the open door):**
```kql
SecurityEvent
| where EventID == 4624 and Account contains "ANONYMOUS"
| order by TimeGenerated desc
```
Result: an `ANONYMOUS LOGON` (TargetUserSid **`S-1-5-7`**, TargetDomainName `WORKGROUP`), **LogonType 3 (Network)**, **NTLM** (`NtLmSsp`), from **`10.50.0.1`** (lab gateway), ~27-10 15:35 UTC. This is a login with no identity — exactly what anonymous SMB access to the share looks like.

**b) The failed logons (being locked out / getting back):**
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, LogonType, IpAddress, WorkstationName, FailureReason
| order by TimeGenerated desc
```
Result: repeated `svc_deploy` failures on `WKS-L62`, LogonType 10 (RDP) and 3 (Network), from `10.50.0.1`, FailureReason `%%2313` = *"unknown user name or bad password."* (Honest note: many of these are my own recovery attempts with the wrong seat's password — the logs show the classic *many failures → eventual success* shape.)

**c) The successful logon (my way back in):**
```kql
SecurityEvent
| where EventID == 4624 and Account has "svc_deploy"
| order by TimeGenerated desc
```
Result: `WKS-L62\svc_deploy` logged on successfully, first success 29-10 ~15:52 UTC, AuthenticationPackage **NTLM**/Negotiate, from `10.50.0.1`.

**The gap (what my monitoring did NOT see):** Sentinel recorded the anonymous access, the failed logons and the successful logon, but **not the commands run once inside**. Default logging captures authentication, not process/command execution — the same blind spot as Mission 2. Everything came over the gateway `10.50.0.1` using **NTLM**, not Kerberos.

---

## 5. MITRE ATT&CK mapping

| Stage | Technique | ID |
|-------|-----------|----|
| Port scan of the workstation | Network Service Discovery | **T1046** |
| Anonymous access to SMB share | Network Share Discovery | **T1135** |
| Credentials left in a readable file | Unsecured Credentials: Credentials In Files | **T1552.001** |
| GPP cpassword in SYSVOL | Unsecured Credentials: Group Policy Preferences | **T1552.006** |
| Using the recovered local admin account | Valid Accounts (Local) | **T1078.003** |
| RDP back into the workstation | Remote Services: Remote Desktop Protocol | **T1021.001** |
| Intruder's staged employee data | Data Staged | **T1074** |

---

## 6. Control gaps and fixes

| Weakness used | Missing control (ISO 27001:2022 Annex A) | NIS2 / CyFun | Fix |
|---------------|------------------------------------------|--------------|-----|
| Anonymous/guest SMB access to a share | A.5.15 Access control; A.8.3 Information access restriction | Access control (NIS2 Art. 21.2.i) | Disable guest/anonymous SMB; restrict share permissions to named groups |
| Credentials stored in a readable file | A.5.17 Authentication information; A.8.3 | Secure credential handling | Never store passwords in files; use a secrets vault |
| GPP `cpassword` in SYSVOL (reversible) | A.8.24 Use of cryptography; A.5.17 | Cryptography (NIS2 Art. 21.2.h) | Remove all GPP cpassword (MS14-025); deploy **LAPS** for local-admin passwords |
| SMB signing not required | A.8.20 Network security; A.8.21 Security of network services | Network security | Enforce SMB signing (required, not just enabled) |
| Legacy privileged local account with a static secret | A.8.2 Privileged access rights; A.5.16 Identity management | Identity & access management | Remove legacy admin accounts; rotate & vault service-account secrets |
| Employee data staged for exfiltration | A.8.12 Data leakage prevention; A.5.14 Information transfer | Incident handling & data protection | DLP + egress filtering; restrict who can read the data at rest |

---

## 7. Data breach assessment

The intruder had **staged employee data ready to leave the network**: `staging\employees.csv`, marked `EXFIL-TEST-MARKER-M3`. It contained **4 employee records** with columns **employee_id, full_name, email, department, salary**. (The dataset is simulated lab data — `example.com` addresses — but is analysed here as if it were a real breach.)

- **What was exposed:** personal data (names, emails) plus **salary** (sensitive HR/financial data) for 4 employees.
- **NIS2 notification duty:** report to the national CSIRT/competent authority — **early warning within 24 h**, **incident notification within 72 h**, final report within one month (NIS2 Art. 23).
- **GDPR notification duty:** notify the supervisory authority **within 72 h** of becoming aware (Art. 33); because salary data raises the risk to individuals, notify the affected people without undue delay (Art. 34).
- **Control that should have stopped the data leaving:** Data Leakage Prevention / egress filtering (ISO 27001 A.8.12), plus access restriction at rest (A.8.3).

There is evidence of **staging** (the file was gathered and ready), but no evidence in my workstation's logs of actual **exfiltration** leaving the network.

---

## 8. Stretch (optional)

Not performed in this iteration. A second, independent way back into the machine (a different leftover or foothold) could be added here as an alternative route.

---

## Appendix — CTFd flags (engine, not the hand-in)

| Challenge | Flag | Status |
|-----------|------|--------|
| First foothold | `HAM{anon_smb_seat62}` | submitted |
| Privileged return | `HAM{admin_rdp_seat62}` | submitted |
| Proof on the desktop | `HAM{desktop_proof_seat62}` | submitted |
| The climax | `HAM{gpp_cpassword_seat62}` | submitted |
| Recon | — | pending (optional) |
