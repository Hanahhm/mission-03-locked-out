# Mission 3 — "Locked out" · Incident Case File

**Analyst:** Hanah Marroun
**Date:** 2026-10-30 (revised 2026-11-04 after coach feedback)
**Environment:** BeCode Hamilton lab
**Target workstation:** `WKS-L62.hamilton.corp` (`10.50.0.62`), seat 62
**Domain controller:** `DC01` (`10.50.0.10`), domain `hamilton.corp`
**Attack machine:** Kali Linux (VirtualBox) reaching the lab over Tailscale

---

## 1. Executive summary — for a manager

I was locked out of my own workstation and of my security monitoring: both logins had been changed, but the machine was still reachable on the network. By taking inventory of what it still exposed, I found a file-sharing service (SMB) open to **anonymous access**. A shared folder held a training account's password in a readable file; that small account was enough to read a domain configuration area (SYSVOL) where an administrative password had been stored in a **reversible, publicly-documented format** (GPP cpassword). Recovering the password for my own workstation gave me back administrative access.

Once back in, I recovered three things left on the desktop: the **proof** of access, the **new monitoring login** (which I rotated immediately), and a **staged set of employee data** the intruder had prepared to steal.

**The single most important risk this exposed:** the reversible admin password was not a one-off. SYSVOL held **one copy per workstation**, readable by **any domain user** — so the same weakness exposes the local-administrator password of **every machine in the domain**, not just mine. Combined with a personal-data set already staged for exfiltration, this is a **Critical** finding (see §5).

---

## 2. Technical narrative — for a technician

- **Stage 1 — seeing what was still exposed.** With my normal access revoked, I inventoried the services the workstation still offered from the network. Only two were open: **SMB (445)** and **RDP (3389)**. RDP is the screen service I already knew, so the thread to pull was SMB. The SMB fingerprint also showed **message signing enabled but not required** — noted as a weakness, though not used in this chain (see §4).

- **Stage 2 — getting a first foothold.** SMB allowed an **anonymous (guest) session** with no credentials. Inside a `Public` share, a readable file held the credentials of a **temporary training account** (`training01`, marked "to be rotated"). Credentials must never sit in a readable file on an anonymously-accessible share. *My Sentinel recorded an `ANONYMOUS LOGON` (SID `S-1-5-7`, LogonType 3, NTLM) from `10.50.0.1`, ~27-10 15:35 UTC (SecurityEvent 4624).* **Attribution caveat:** I cannot prove this event was the intruder rather than my own anonymous test — `10.50.0.1` is the lab gateway that **every actor is NAT-ed behind**, mine included. The only discriminator is timing: it predates my own recovery work (29–30-10), so it is consistent with the original intrusion, but I treat it as **probable**, not proven.

- **Stage 3 — finding the real key.** The training account was low-privileged, but **any domain account can read SYSVOL** on the domain controller, where Group Policy lives. SYSVOL held a **GPP `cpassword`** — a password encrypted with an **AES key Microsoft itself published** (MS14-025), so it is reversible by anyone. Critically, there was **one `Groups.xml` per seat**, each with the reversible password of a local administrator account (`svc_deploy`). I decrypted the one for **my own seat (62)** and recovered its password. *This step happened on the DC, off my workstation, so it is reconstructed from my own actions rather than from my SIEM.* **Lesson learned:** I first decrypted another seat's file and its password was rejected by my machine — SYSVOL has one per workstation, and `svc_deploy` is a **local** account, so you must use your own seat's copy.

- **Stage 4 — walking back in.** I used the recovered local-admin credential to RDP back into my workstation. The connection first failed under NLA; the fix was the client's security mode (forcing TLS), not the credential. This landed me on my own desktop as a local administrator. *My Sentinel shows the classic shape of this reprise: repeated `svc_deploy` logon failures followed by a success (SecurityEvent 4625 → 4624, 29-10). Note: many of those failures are my own recovery attempts with the wrong seat's password — an honest read of the data.*

- **Stage 5 — taking my proof and seeing what they were after.** Three items sat on the desktop: the **proof of access**; the **new monitoring (Sentinel) login**, which I signed into once and then **rotated immediately** per the first-reflex rule; and a **staged employee dataset** the intruder had gathered and parked, ready to exfiltrate (assessed as a data breach in §5).

**On monitoring coverage.** Process-creation auditing (**Event 4688**) is enabled on this workstation and has been since Mission 2, so host-level process and command execution **is** visible in my SIEM — there is no logging blind spot here. The only steps outside my view are those that happened on the **domain controller / SYSVOL**, which is off my workstation. All on-host authentication came over the gateway `10.50.0.1` using **NTLM**, not Kerberos.

---

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I did | Where I can prove it |
|---|---|---|---|---|
| 1 — exposure | Discovery | **T1046** Network Service Discovery | Inventoried exposed services; found SMB + RDP open | Reconstructed from my own actions (scan ran from Kali) |
| 2 — foothold | Discovery / Credential Access | **T1135** Network Share Discovery; **T1552.001** Unsecured Credentials: Credentials In Files | Anonymous SMB into `Public`; read a training account from a file | SecurityEvent 4624 (`ANONYMOUS LOGON`) — attribution caveat, §2 |
| 3 — the key | Credential Access | **T1552.006** Unsecured Credentials: Group Policy Preferences | Read SYSVOL; decrypted my seat's reversible GPP cpassword | Reconstructed from my own actions (SYSVOL read on the DC) |
| 4 — reprise | Initial Access / Lateral Movement | **T1078.003** Valid Accounts: Local Accounts; **T1021.001** Remote Services: RDP | RDP back in with the recovered local-admin credential | SecurityEvent 4625 → 4624 (`svc_deploy`, 29-10) |
| 5 — proof + staged data | Collection | **T1074** Data Staged; **T1005** Data from Local System | Recovered proof + monitoring login; found staged employee data | Files recovered on the host; staging observed on disk |

---

## 4. Control gaps & remediation

*One row per weakness actually used in this chain.*

| Weakness exploited | Why it worked | Missing control + fix | ISO 27001:2022 Annex A | NIS2 / CyFun |
|---|---|---|---|---|
| Anonymous/guest SMB access to a share | Guest sessions were allowed, so no identity was needed | Disable guest/anonymous SMB; restrict share permissions to named groups | A.5.15 Access control; A.8.3 Information access restriction | Access control (Art. 21.2.i) |
| Credentials stored in a readable file | A password sat in plain text on an open share | Never store passwords in files; use a secrets vault | A.5.17 Authentication information; A.8.3 | Secure credential handling |
| GPP `cpassword` in SYSVOL (reversible) | Encrypted with a key Microsoft published; readable by any domain user; one per seat | Remove all GPP cpassword (MS14-025); deploy **LAPS** for local-admin passwords | A.8.24 Use of cryptography; A.5.17 | Cryptography (Art. 21.2.h) |
| Legacy privileged **local** account with a static secret | A reusable local-admin secret existed on every seat | Remove legacy admin accounts; rotate & vault service-account secrets; least privilege | A.8.2 Privileged access rights; A.5.16 Identity management | Identity & access management |
| Employee data staged, no egress control | Data could be gathered and parked ready to leave | DLP + egress filtering; restrict who can read the data at rest | A.8.12 Data leakage prevention; A.5.14 Information transfer | Incident handling & data protection |

**Other weaknesses observed (not part of this attack chain).** Worth recording even though the intrusion did not rely on it:
- **SMB signing enabled but not required** (seen in the Stage 1 fingerprint). It leaves the host open to SMB relay / man-in-the-middle attacks. Fix: enforce SMB signing as **required**, not merely enabled (ISO 27001 A.8.20 / A.8.21).

---

## 5. Data breach assessment

- **What was exposed.** A staged file (`staging\employees.csv`, marked `EXFIL-TEST-MARKER-M3`) with **4 employee records** — `employee_id`, `full_name`, `email`, `department`, `salary`. That is personal data (names, emails) combined with **salary** (sensitive HR/financial data). The dataset is simulated lab data (`example.com` addresses) but is analysed here as a real breach.

- **Severity.** **Critical.** Who would be harmed and how: the 4 employees face a **high risk** — identity data plus salary enables targeted phishing, fraud and social engineering against them. Beyond this file, the GPP weakness that enabled the intrusion exposes **every workstation's local-admin password** to any domain user, so the blast radius is domain-wide, not a single host.

- **Notification duty under NIS2.** Report to the national CSIRT/competent authority — **early warning within 24 h**, **incident notification within 72 h**, final report within one month (Art. 23). *Why it applies:* these duties attach when the organisation is an **essential or important entity** in a covered sector (in scope) **and** the incident is **"significant"** — capable of serious operational disruption or financial loss, or of affecting others. Domain-wide admin exposure plus a staged personal-data set clears the "significant" threshold.

- **Obligations under GDPR.** Personal data was involved, so this triggers GDPR. Notify the supervisory authority **within 72 h** of becoming aware (Art. 33), **and** notify the affected individuals without undue delay (Art. 34). *Why Art. 34 applies:* individual notification is required when the breach is likely to be a **high risk to people's rights and freedoms** — met here because the data combines identity with salary, enabling fraud and targeted attacks.

- **Missing control.** The data should never have been collectable and parked with no egress control. Fix: **Data Leakage Prevention / egress filtering** (ISO 27001 A.8.12) plus **access restriction at rest** (A.8.3), so the data cannot be read in bulk or staged for exfiltration.

---

## 6. Stretch — alternative route (optional)

Not performed in this iteration. A second, independent way back onto the machine (a different leftover credential or foothold) could be added here as an alternative route, described the same way as the main chain.

---

## Appendix — CTFd progress (status only, not the hand-in)

| Challenge | Status |
|-----------|--------|
| First foothold | submitted |
| Privileged return | submitted |
| Proof on the desktop | submitted |
| The climax | submitted |
| Recon | pending |

*(Flag values are deliberately not reproduced here — the report, not the flag, is the deliverable.)*
