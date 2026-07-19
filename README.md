![Banner](images/banner.png)


# SOC Investigation Report — Weekend Alert Correlation (`admin_backup`)

**Case ID:** TKT-2026-04340 — *Weekend correlation review*
**Classification:** Suspected valid-account compromise → privilege escalation → data exfiltration
**Analyst:** Leonardo Romero
**Escalated to:** Roberto Silva, SOC Manager
**Status:** Contained (initial response) — root cause and attribution still open

---

## 1. Scenario

Monday, 09:00. Five critical alerts generated between Friday and Saturday had each been closed as a false positive by a different analyst, on a different shift, investigated in isolation. An open ticket asked for a weekend correlation review. The standing question from the SOC Manager: individually-closed false positives don't matter if, taken together, they tell a different story.

This investigation re-opens all five alerts as a single correlation exercise rather than accepting the prior individual closures.

## 2. Objective

Determine whether the five alerts represent five unrelated, correctly-closed false positives, or a single missed campaign — and produce a decision (contain / escalate / monitor) supported by evidence, under a 25-minute reporting deadline to the SOC Manager.

## 3. Data Sources & Methodology

This investigation was built from **structured incident tickets containing embedded forensic log excerpts** (Active Directory, perimeter firewall, EDR, proxy/DNS, email gateway), rather than direct, live queries against a SIEM console. Each ticket packaged the relevant log lines as already-collected evidence; the analytical work was to correlate those excerpts across tickets, identify the shared entities, and resolve conflicts between sources — the same correlation discipline used in a live SOC, applied to pre-collected evidence rather than a live query interface.

Sources referenced across the investigation: **Active Directory, perimeter firewall, proxy/DNS resolution logs, EDR, email gateway, ITSM, CMDB, corporate change calendar.**

Findings below follow a strict three-tier confidence model — **CONFIRMED** (directly evidenced in logs), **PROBABLE** (supported by correlated indicators but not independently verified), and **UNKNOWN** (evidence required, not currently available) — consistent with NIST SP 800-61 detection & analysis practice of separating verified fact from working hypothesis.

## 4. Key Findings

### Confirmed
- `admin_backup` was locked out after 15 failed login attempts (Fri 14:25:11), then successfully authenticated from internal IP `10.50.8.45` at Fri 14:48:03.
- ~50 GB was transferred from `srv-backup-01` to external IP `203.0.113.45` over HTTPS/443 (Fri 22:15–22:45), preceded by resolution of a previously unseen domain (`cdn-us-east-19.streamcloud.io`) to that same IP.
- `powershell.exe -EncodedCommand` executed twice under anomalous parent-process lineage: once under `rsync.exe` (Fri 22:12, immediately before the external connection) and once under `scheduled_task_runner.exe` (Sat 02:28, two minutes before a firewall rule change).
- A new firewall rule permitting inbound/outbound traffic on port 443 from `srv-backup-01` was added, saved, and reloaded using `admin_backup` credentials (Sat 02:30), with no associated change ticket.
- `admin_backup` was added to the `Domain_Admins` group via `net.exe localgroup "Domain Admins" admin_backup /ADD`, executed from `powershell.exe`; the change replicated successfully between domain controllers (Sat 06:00).
- No emails sent or received by `admin_backup` in the Fri–Sat window; the account has no mailbox enabled — phishing as an initial-access vector for this account is ruled out.

### Probable
- The chain above is consistent with **valid-account compromise or privilege abuse using `admin_backup` credentials**, with `powershell.exe` acting as the common execution mechanism linking reconnaissance (hash access), exfiltration, firewall persistence, and privilege escalation.
- A quarterly password rotation (`CHG-2026-1842`, prior Monday) is a plausible explanation for the initial failed-login lockout — **referenced but not independently verified against ITSM/CMDB records.**

### Unknown / Open Items
- **Initial access vector** — not determined. Whether the Friday 14:48 login represents the legitimate account owner using a freshly-rotated password, or an attacker already in possession of valid credentials, is unresolved.
- **Ownership/attribution of source IP `10.50.8.45`** — not confirmed against asset inventory or CMDB. Whether this is the account owner's normal endpoint, a shared workstation, or a jump host materially changes the read on this incident.
- **SIEM vs. firewall timestamp discrepancy** — the SIEM reports the exfiltration window as under 30 minutes; firewall logs show three separate transfer windows spread across several hours (Fri 22:15–22:45, Sat 03:00–03:45, Sat 07:30–07:45). Not yet resolved — requires NTP sync verification, per-device timezone/clock configuration check, and SIEM log-aggregation-delay review across all sources before it can be treated as either a clock artifact or a second wave of activity.
- **Authorization for the firewall change and group modification** — no associated change ticket for either action; the change calendar was last updated two weeks prior to the incident, so its absence of a scheduled maintenance window is not, by itself, conclusive.

## 5. Attack Narrative (High-Level)

`admin_backup` authenticated successfully from an internal address after a lockout caused by repeated failed logins. The session accessed backup-configuration resources and AD hash data, then — hours later, following a documented evidence gap — executed an encoded PowerShell command that established an outbound connection to a newly-resolved external domain/IP, coinciding with a ~50 GB transfer. Early Saturday morning, a second PowerShell execution preceded both a new firewall rule opening port 443 from the same server and the addition of the account to `Domain_Admins`. Every event in this chain shares the same account and the same source host, which is the basis for treating the five alerts as one incident rather than five isolated ones.

**Declared evidence gap:** Fri 14:50 – 22:10 — the session remained active but is not covered by available logs; no intermediate activity is asserted for this window.

## 6. Key Indicators (Quick Reference)

| Type | Value | Confidence |
|---|---|---|
| Account | `admin_backup` | Confirmed — common thread across all 5 alerts |
| Host | `srv-backup-01` | Confirmed — source of all post-login activity |
| Internal IP | `10.50.8.45` | Confirmed login source; owner/device attribution unknown |
| External IP | `203.0.113.45` | Confirmed exfiltration destination; no prior organizational history |
| Domain | `cdn-us-east-19.streamcloud.io` | Confirmed, newly observed, resolves to the IP above |
| Process | `powershell.exe -EncodedCommand` (parents: `rsync.exe`, `scheduled_task_runner.exe`) | Confirmed, anomalous lineage |
| AD Change | `net.exe localgroup "Domain Admins" admin_backup /ADD` | Confirmed |

Full indicator list with source, first/last seen, and MITRE ATT&CK technique mapping: see [`05-ioc-mitre-mapping.md`](05-ioc-mitre-mapping.md).

## 7. Investigation Constraints (Scope Cut at Time of Reporting)

**Not done today:** full forensic imaging of `srv-backup-01`, attacker attribution, confirmation of initial access vector.

**Would change the assessment:** confirmation of an authorized maintenance window; evidence the transfer was a legitimate backup job; confirmation from the account owner that they performed all observed actions; evidence of a second compromised account or persistence elsewhere in the environment.

## 8. Repository Structure

| File | Contents |
|---|---|
| `README.md` | This file — case overview, findings summary, methodology |
| [`01-triage-matrix.md`](01-triage-matrix.md) | Per-alert triage: rule hypothesis, signal/noise call, severity re-scoring, correlation points |
| [`02-scope-note.md`](02-scope-note.md) | Initial 25-minute scope note delivered to the SOC Manager |
| [`03-timeline.md`](03-timeline.md) | Correlated timeline with CONFIRMED/PROBABLE/UNKNOWN tagging and declared clock/evidence gaps |
| [`04-executive-report.md`](04-executive-report.md) | Final executive report (Confirmed / Probable / Unknown / Actions) |
| [`05-ioc-mitre-mapping.md`](05-ioc-mitre-mapping.md) | Consolidated IOC list and MITRE ATT&CK technique mapping |

## 9. Skills Demonstrated

- Cross-source correlation of independently-closed alerts into a single incident narrative
- Evidence-tiered reporting (CONFIRMED / PROBABLE / UNKNOWN) instead of overstating or underselling findings
- Identification and explicit documentation of a data-source conflict (SIEM vs. firewall timestamps) without resolving it beyond the evidence available
- Time-boxed executive communication under a supervisor deadline
- Containment decision-making grounded in available evidence rather than default escalation
