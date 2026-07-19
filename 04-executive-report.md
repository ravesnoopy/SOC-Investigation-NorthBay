# 04 · Executive Report — TKT-2026-04340

**To:** Roberto Silva, SOC Manager
**From:** Leonardo Romero, SOC Analyst
**Subject:** Weekend correlation review — five alerts, one incident
**Case ID:** TKT-2026-04340
**Report date:** Saturday, July 18, 2026 — 09:00
**Classification:** Internal — Restricted

---

> **Reading time: under 2 minutes.** This report follows a fixed four-block structure: what is confirmed, what is probable, what remains unknown, and what actions are required. Supporting detail is in the linked investigation files.

---

## ✓ CONFIRMED — Facts with source

**Account activity:**
`admin_backup` was locked out after 15 failed login attempts (Fri 14:25:11, AD) and authenticated successfully from internal IP `10.50.8.45` at Fri 14:48:03 (AD). The session remained active for over 15 hours.

**Data exfiltration:**
~50 GB transferred from `srv-backup-01` to external IP `203.0.113.45` over HTTPS/443 between Fri 22:15 and 22:45 (Firewall, SIEM). The destination domain `cdn-us-east-19.streamcloud.io` resolved to that IP two minutes prior and has no prior history in the organization (Proxy/DNS). No authorized backup job or change ticket covers this transfer.

**Execution mechanism:**
`powershell.exe -EncodedCommand` executed twice during the session — at Fri 22:12 under `rsync.exe` (EDR), and at Sat 02:28 under `scheduled_task_runner.exe` (EDR) — immediately preceding the exfiltration and the firewall modification respectively. Payload content not recovered.

**Unauthorized firewall change:**
A new rule permitting outbound traffic to any destination on port 443 was added, saved, and reloaded using `admin_backup` credentials at Sat 02:30 (Firewall). No associated change ticket. No authorized maintenance window on record.

**Privilege escalation:**
`admin_backup` added itself to `Domain_Admins` via `net.exe localgroup "Domain Admins" admin_backup /ADD`, executed from `powershell.exe` at Sat 05:58 (EDR). The change was replicated between domain controllers and confirmed complete at Sat 06:01 (AD).

---

## ? PROBABLE — Hypothesis with supporting indicators

The full event chain is consistent with **valid-account compromise**: an attacker obtained `admin_backup` credentials prior to Friday, used them to access the backup server, extracted sensitive data and AD hashes, established a persistent outbound channel via an unauthorized firewall rule, and escalated to domain administrator level before closing the session.

`powershell.exe -EncodedCommand` is the consistent execution mechanism linking all three critical actions — exfiltration, firewall modification, and privilege escalation — suggesting a scripted or automated attack chain rather than manual, ad-hoc actions.

The quarterly password rotation (CHG-2026-1842, prior Monday) is a plausible explanation for the initial lockout by the legitimate account owner — but this does not exclude the possibility that an attacker with a pre-obtained password also triggered lockout before the owner successfully authenticated, or that the successful login at 14:48 was the attacker using freshly-obtained credentials after the rotation.

---

## ✗ UNKNOWN — Open gaps requiring evidence

**Initial access vector:** How the `admin_backup` credentials were obtained is not determined. Phishing is ruled out (no mailbox, no email activity). Credential theft via a prior compromise, pass-the-hash from another host, or insider access remain open hypotheses. None can be confirmed or excluded with current evidence.

**Identity of `10.50.8.45`:** The source device of the Friday login has not been confirmed against asset inventory or CMDB. If this is the legitimate account owner's workstation, the timeline reads differently than if it is an attacker-controlled host or a shared jump server. This is a priority gap.

**Encoded PowerShell payload:** The content of both `-EncodedCommand` executions is not recovered in the available evidence. Decoding these payloads would significantly advance understanding of what actions were automated during the session.

**SIEM vs. firewall timestamp discrepancy:** The SIEM records a single exfiltration event under 30 minutes; the firewall logs show three transfer windows totaling ~72.6 GB across approximately 9 hours. If the firewall data is accurate, both the total data-exposure volume and the active incident window (potentially extending to Sat 07:45) are larger than the SIEM suggests. Root cause of discrepancy not yet determined — NTP sync, timezone configuration, and SIEM aggregation delay all require verification.

**Post-escalation activity:** No lateral movement or use of the elevated `Domain_Admins` privileges is confirmed in the current evidence set. Absence of evidence is not evidence of absence — a broader scope review is required.

---

## → ACTIONS

### Immediate — Execute before end of business today

| # | Action | Owner | Rationale |
|---|---|---|---|
| 1 | Disable `admin_backup` credentials and invalidate active sessions | Identity / IAM | Stops any ongoing access under this account |
| 2 | Remove `admin_backup` from `Domain_Admins` and verify replication on both DCs | Active Directory team | Revokes the escalated privileges confirmed at Sat 06:01 |
| 3 | Revert and block the unauthorized firewall rule (`dst=any:443 action=allow`, Sat 02:30) | Network / Firewall team | Closes the persistence channel opened during the incident |
| 4 | Block `203.0.113.45` and `cdn-us-east-19.streamcloud.io` at the perimeter | Network / Firewall team | Prevents any additional outbound communication to the confirmed exfiltration destination |
| 5 | Preserve memory and disk state of `srv-backup-01` — do not reboot or remediate before forensic imaging | IR / Forensics | Evidence preservation per NIST SP 800-61 — remediation before imaging destroys the ability to recover the PowerShell payload and session artifacts |

### To Close Open Gaps — Before final incident report

| # | Action | Owner | Rationale |
|---|---|---|---|
| 6 | Decode both `powershell.exe -EncodedCommand` instances (Fri 22:12, Sat 02:28) | IR / Forensics | Recovers the attack chain logic; may identify additional TTPs or staged payloads |
| 7 | Confirm ownership of `10.50.8.45` against CMDB and asset inventory | Infrastructure | Resolves whether the Friday login source was the legitimate owner's device or an attacker-controlled host |
| 8 | Verify NTP synchronization, per-device timezone configuration, and SIEM aggregation settings across `srv-backup-01`, the perimeter firewall, and the SIEM collector | Infrastructure / SIEM team | Resolves the SIEM/firewall timestamp discrepancy and confirms actual exfiltration volume and window |
| 9 | Verify CHG-2026-1842 against ITSM records | Change Management | Confirms whether the password rotation covers the account lockout behavior or not |
| 10 | Conduct environment-wide review for `admin_backup` activity and `203.0.113.45` connections on hosts other than `srv-backup-01` | SOC | Rules out lateral movement and additional compromise scope |

---

## Investigation Files

| File | Contents |
|---|---|
| [`01-triage-matrix.md`](01-triage-matrix.md) | Per-alert re-evaluation with signal/noise call, severity re-scoring, and correlation rationale |
| [`02-scope-note.md`](02-scope-note.md) | Initial 25-minute scope note with containment decision rationale and data-conflict documentation |
| [`03-timeline.md`](03-timeline.md) | Full correlated timeline with confidence tagging, declared evidence gaps, and clock-conflict analysis |
| [`05-ioc-mitre-mapping.md`](05-ioc-mitre-mapping.md) | Consolidated IOC list and MITRE ATT&CK technique mapping |
