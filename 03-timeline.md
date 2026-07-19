# 03 · Correlated Timeline — TKT-2026-04340

**Case:** TKT-2026-04340
**Analyst:** Leonardo Romero
**Method:** Cross-source correlation of log excerpts embedded in five independently-closed tickets. Events normalized by logical sequence; clock conflicts documented rather than silently resolved.

---

## Confidence Model

| Label | Meaning |
|---|---|
| **CONFIRMED** | Event directly evidenced by a discrete log entry in the available sources |
| **INFERRED** | Supported by correlated indicators but not confirmed by a standalone log entry |
| **UNKNOWN** | Gap in available evidence — declared explicitly; no event asserted |

---

## Clock Conflict Notice

A material discrepancy exists between SIEM and firewall timestamps for the exfiltration window. The SIEM records the transfer as a single event under 30 minutes; the firewall shows three separate windows across approximately 9 hours. **Timestamps in this timeline are reproduced as logged — no manual adjustment has been applied.** The discrepancy is documented in Section 2 below and must be resolved by the Infrastructure team (NTP sync verification, per-device timezone/UTC offset audit, SIEM aggregation-delay review) before this timeline can be considered authoritative for a forensic proceeding.

---

## 1. Event Timeline

### Friday

| Time (as logged) | Source | Confidence | Event |
|---|---|---|---|
| 14:25:11 | Active Directory | **CONFIRMED** | `admin_backup` reaches the 15-attempt lockout threshold. Account locked. |
| 14:48:03 | Active Directory | **CONFIRMED** | Successful login: `admin_backup` from `10.50.8.45`, post-unlock. Session begins. Internal IP — device owner not confirmed against asset inventory. |
| ~14:50 | Active Directory | **INFERRED** | Access to `\\srv-backup-01\Backup_Config\`. AD hash data read during the same session. No discrete log entry confirms the exact timestamp; derived from alert context in TKT-04118. |
| 22:12 | EDR | **CONFIRMED** | `powershell.exe -EncodedCommand` executed. Parent process: `rsync.exe`. Anomalous lineage — a backup sync process spawning an encoded PowerShell command is not expected behavior. Payload not recovered in available evidence. |
| 22:14 | Proxy / DNS | **CONFIRMED** | DNS resolution: `cdn-us-east-19.streamcloud.io` → `203.0.113.45`. Domain has no prior resolution history in the organization. |
| 22:15:08 | Firewall | **CONFIRMED** | Outbound connection established: `srv-backup-01:51234 → 203.0.113.45:443`. |
| 22:16:42 | Firewall | **CONFIRMED** | `DATA_OUT srv-backup-01 → 203.0.113.45` — 2.3 GB |
| 22:21:15 | Firewall | **CONFIRMED** | `DATA_OUT srv-backup-01 → 203.0.113.45` — 8.7 GB |
| 22:34:22 | Firewall | **CONFIRMED** | `DATA_OUT srv-backup-01 → 203.0.113.45` — 18.4 GB |
| 22:42:18 | Firewall | **CONFIRMED** | `DATA_OUT srv-backup-01 → 203.0.113.45` — 20.6 GB |
| 22:15–22:45 | Firewall (aggregated) | **CONFIRMED** | First exfiltration window closes. Total transferred in this window: **~50.0 GB**. |

---

### Friday 22:45 – Saturday 02:27 — DECLARED EVIDENCE GAP

> **No log entries available for this interval in the current evidence set.**
> The session under `admin_backup` remained active — confirmed by the continuity of subsequent events — but intermediate actions during this window cannot be reconstructed from available sources. No events are asserted for this period.
> This gap must be addressed by EDR full-session review and firewall connection-state logs before the timeline can be considered complete.

---

### Saturday

| Time (as logged) | Source | Confidence | Event |
|---|---|---|---|
| 02:28 | EDR | **CONFIRMED** | `scheduled_task_runner.exe` launches `powershell.exe -EncodedCommand`. Second encoded PowerShell execution of the session, now under a scheduled task parent. Payload not recovered. |
| 02:30:15 | Firewall | **CONFIRMED** | `FW_RULE_ADD by=admin_backup src=srv-backup-01 dst=any:443 action=allow`. No change ticket. No authorized maintenance window on record. |
| 02:30:18 | Firewall | **CONFIRMED** | `FW_CONFIG_SAVE by=admin_backup` |
| 02:30:22 | Firewall | **CONFIRMED** | `FW_RELOAD success` |
| 03:00–03:45 | Firewall | **CONFIRMED** | Second outbound transfer window: `srv-backup-01 → 203.0.113.45:443` — **18.4 GB**. *(See clock conflict notice — this window is not reflected in SIEM data.)* |
| 05:58 | EDR | **CONFIRMED** | `powershell.exe` executes `net.exe localgroup "Domain Admins" admin_backup /ADD`. |
| 06:00:42 | Active Directory | **CONFIRMED** | `AD_GROUP_MODIFY user=admin_backup group=Domain_Admins action=ADD executed_by=admin_backup source_host=srv-backup-01` |
| 06:00:45 | Active Directory | **CONFIRMED** | `AD_REPLICATION_START dc01 → dc02` |
| 06:01:12 | Active Directory | **CONFIRMED** | `AD_REPLICATION_COMPLETE`. `Domain_Admins` membership change fully propagated. Session activity after this point: **UNKNOWN** — no further events confirmed in available logs. |
| 07:30–07:45 | Firewall | **CONFIRMED** | Third outbound transfer window: `srv-backup-01 → 203.0.113.45:443` — **4.2 GB**. *(See clock conflict notice — this window is not reflected in SIEM data. Occurred after the last confirmed AD event.)* |

---

## 2. Clock Conflict — SIEM vs. Firewall

| Parameter | SIEM | Firewall |
|---|---|---|
| Exfiltration event count | 1 | 3 |
| First window | Fri ~22:15–22:45 | Fri 22:15–22:45 |
| Additional windows | None | Sat 03:00–03:45 / Sat 07:30–07:45 |
| Total volume reported | ~50.0 GB | ~72.6 GB |

**Current status:** Unresolved. No timestamps were modified for this timeline.

**Possible technical causes (to be verified by Infrastructure):**
- NTP desynchronization between the SIEM collector and the firewall
- Per-device UTC offset or local-time misconfiguration
- SIEM log aggregation compressing multiple events into a single record
- Log collection latency causing firewall events to arrive outside the SIEM correlation window

**Analytical impact:** The conflict does not change the signal determination for TKT-04156 (exfiltration confirmed regardless of which source is accurate), but it does affect total data-exposure volume and may indicate that the third transfer window (Sat 07:30–07:45) occurred after the Domain Admins group change — which would extend the active incident window beyond Sat 06:01.

---

## 3. Cumulative Exfiltration Volume

| Window | Volume | Source | Status |
|---|---|---|---|
| Fri 22:15–22:45 | ~50.0 GB | Firewall + SIEM | Confirmed by both sources |
| Sat 03:00–03:45 | 18.4 GB | Firewall only | Confirmed in firewall; absent in SIEM — clock conflict |
| Sat 07:30–07:45 | 4.2 GB | Firewall only | Confirmed in firewall; absent in SIEM — clock conflict |
| **Total (if all firewall windows valid)** | **~72.6 GB** | Firewall | Pending conflict resolution |
| **Total (SIEM only)** | **~50.0 GB** | SIEM | Confirmed by SIEM; may be undercount |

---

## 4. Shared Entities Across the Full Timeline

| Entity | First Seen | Last Seen | Role |
|---|---|---|---|
| `admin_backup` | Fri 14:25:11 | Sat 06:00:42 | Account used in every event across all five tickets |
| `srv-backup-01` | Fri 14:48:03 | Sat 06:00:42 | Source host for all post-login activity |
| `10.50.8.45` | Fri 14:48:03 | Fri 14:48:03 | Login source IP; internal; device owner unconfirmed |
| `203.0.113.45` | Fri 22:14 | Sat 07:45 | Exfiltration destination; no prior org history |
| `cdn-us-east-19.streamcloud.io` | Fri 22:14 | Fri 22:14 | Domain resolved to `203.0.113.45`; newly observed |
| `powershell.exe -EncodedCommand` | Fri 22:12 | Sat 05:58 | Execution mechanism across exfiltration, firewall change, and privilege escalation |

---

## 5. Narrative Summary

At 14:48 on Friday, `admin_backup` authenticated successfully to `srv-backup-01` from an internal address following a lockout caused by repeated failed logins. The session accessed backup configuration data and AD hash information. After a gap of approximately 7 hours with no confirmed intermediate log entries, an encoded PowerShell command executed under the `rsync.exe` process — two minutes before an outbound connection was established to a previously-unseen external IP and domain, coinciding with a ~50 GB data transfer over HTTPS.

In the early hours of Saturday, a second encoded PowerShell execution under a scheduled task preceded the addition of a firewall rule permanently opening port 443 from the backup server to any external destination. Two hours later, a third PowerShell execution issued the command to add `admin_backup` to the `Domain_Admins` group; the change was confirmed and replicated between domain controllers by 06:01.

All five originally-closed tickets share the same account, the same host, and the same execution mechanism. The sequence is internally consistent with a single incident progressing from access through reconnaissance, exfiltration, persistence, and privilege escalation — not five independent, unrelated events.
