# High-Volume Shift Triage — Prioritization Exercise

> [!IMPORTANT]
> **Not a single live 8-hour recording.** This document is a **prioritization and alert-fatigue exercise**. It links to the six **live** incident reports (`INC-2026-001` through `INC-2026-006`), each backed by exported artifacts in [`docs/live-evidence-ledger.md`](../docs/live-evidence-ledger.md). Queue times below are **illustrative** for teaching MTTA/MTTC and deduplication — they are **not** a replayed or injected log timeline.

Each core incident was executed **live** on its own UTC window (June 13–18). Background items (login failures, Defender info, GPO refresh) represent normal lab chatter observed during live operations, not copied logs between tools.

---

## What was live during lab operations

| Source | Method |
|--------|--------|
| Endpoint cases (001, 003, 005, 006) | **Apache Caldera** operations on real agents → Wazuh / Sysmon / Splunk / Defender |
| INC-2026-002 | **Live** `emulate_o365spray.py` (no `--mock`) → Entra `SigninLogs` → Sentinel |
| INC-2026-004 | **Live** OpenVPN auth failures on pfSense during CHG-8821 → syslog → Sentinel `VPNLogs` |

---

## Shift triage metrics (exercise)

Illustrative KPIs for prioritization discussion:

| Metric | Value | Definition / Operational Impact |
|--------|-------|---------------------------------|
| **Total Alerts Ingested** | 22 | Alerts in a modeled Tier 1 queue |
| **Mean Time to Acknowledge (MTTA)** | 3m 40s | Ingestion to ticket open |
| **Mean Time to Contain (MTTC)** | 9m 45s | Acknowledge to containment |
| **False Positive Rate** | 63.6% | 14/22 benign or expected noise |
| **Escalations to Tier 2** | 5 | True positives escalated with notes |

---

## Triage strategy & prioritization

1. **Severity 1 (Critical/High): User reports & auth successes**
   - Phishing with attachment ([INC-2026-005](../incidents/INC-2026-005-phishing-chain.md))
   - Password spray with successful logon ([INC-2026-002](../incidents/INC-2026-002-entra-password-spray.md))
   - *Action:* Triage immediately; isolate or revoke within 15 minutes.

2. **Severity 2 (Medium): High-severity endpoint detections**
   - BITS LOLBin ([INC-2026-001](../incidents/INC-2026-001-bits-job-download.md))
   - Scheduled task persistence ([INC-2026-003](../incidents/INC-2026-003-scheduled-task-persistence.md))
   - *Action:* Baseline validation; isolate if LOLBin/persistence confirmed.

3. **Severity 3 (Low): Perimeter scanning & auth noise**
   - VPN mass failures ([INC-2026-004](../incidents/INC-2026-004-false-positive-vpn.md))
   - *Action:* Change management first; bulk-close if maintenance explains spike.

---

## 22-alert queue (illustrative)

Links point to **live** incident reports. Times are for **prioritization practice**, not consolidated evidence.

| Time (UTC) | Source | Alert Summary | Priority | MTTA | Action | Case / Ticket |
|------------|--------|---------------|----------|------|--------|---------------|
| **08:05** | Wazuh | Windows host login failure | Low | 1m | Benign typo; closed | N/A |
| **08:12** | Wazuh | Windows host login failure | Low | 2m | Same host; closed | N/A |
| **08:30** | Splunk | Defender signature update | Info | 5m | Auto-closed | N/A |
| **09:00** | Sentinel | Entra password spray: jsmith | High | 2m | 18 fails + 1 success | [INC-2026-002](../incidents/INC-2026-002-entra-password-spray.md) · [#48305](sample-tickets.md#L36) |
| **09:05** | Sentinel | Entra risky sign-in: jsmith | High | 1m | Revoked sessions; isolated WKSTN-042 | [INC-2026-002](../incidents/INC-2026-002-entra-password-spray.md) · [#48305](sample-tickets.md#L36) |
| **09:15** | Wazuh | AD GPO refresh success | Info | 10m | Baseline noise | N/A |
| **09:40** | Splunk | Firewall admin logon | Normal | 3m | Matched CHG-8815 | N/A |
| **10:10** | Sentinel | Failed VPN logins — 203.0.113.45 | Normal | 4m | 47 live failures (VPN storm) | [INC-2026-004](../incidents/INC-2026-004-false-positive-vpn.md) · [#48322](sample-tickets.md#L86) |
| **10:15** | Sentinel | VPN brute-force threshold | Normal | 2m | Matched CHG-8821 | [INC-2026-004](../incidents/INC-2026-004-false-positive-vpn.md) · [#48322](sample-tickets.md#L86) |
| **10:45** | Wazuh | Windows host login failure | Low | 4m | Dev test; closed | N/A |
| **11:30** | Splunk | SCCM package scan | Info | 8m | Scheduled; closed | N/A |
| **12:15** | User | Phishing report — invoice | High | 4m | Header triage | [INC-2026-005](../incidents/INC-2026-005-phishing-chain.md) · [#48340](sample-tickets.md#L109) |
| **12:22** | Sentinel | PowerShell from Outlook | High | 1m | Isolated WKSTN-042 | [INC-2026-005](../incidents/INC-2026-005-phishing-chain.md) · [#48340](sample-tickets.md#L109) |
| **13:00** | Wazuh | Rule 180001 — BITS on WKSTN-042 | High | 6m | Validated LOLBin | [INC-2026-001](../incidents/INC-2026-001-bits-job-download.md) · [#48291](sample-tickets.md#L11) |
| **13:08** | Splunk | Sysmon EID 11 — payload on disk | High | 2m | Correlated to BITS chain | [INC-2026-001](../incidents/INC-2026-001-bits-job-download.md) · [#48291](sample-tickets.md#L11) |
| **13:45** | Wazuh | AD service account query | Low | 5m | Standard LDAP; closed | N/A |
| **14:10** | Wazuh | Rule 180002 — ChromeUpdate task | High | 3m | Task XML; parent `cmd` → `schtasks` | [INC-2026-003](../incidents/INC-2026-003-scheduled-task-persistence.md) · [#48318](sample-tickets.md#L61) |
| **14:30** | Splunk | Sysmon — `schtasks /Create` | High | 2m | Deleted rogue task | [INC-2026-003](../incidents/INC-2026-003-scheduled-task-persistence.md) · [#48318](sample-tickets.md#L61) |
| **14:40** | Wazuh | Rule 180003 — RDP port WKSTN-099 | High | 2m | Isolated; port revert | [INC-2026-006](../incidents/INC-2026-006-rdp-lateral-movement.md) · [#48370](sample-tickets.md#L129) |
| **14:45** | Wazuh | Rule 180004 — tcpdump on WKSTN-099 | High | 1m | Isolated WKSTN-042; revoked jsmith | [INC-2026-006](../incidents/INC-2026-006-rdp-lateral-movement.md) · [#48370](sample-tickets.md#L129) |
| **15:15** | Wazuh | Windows host login failure | Low | 4m | Closed | N/A |
| **15:50** | User | Shift handoff ticket | Normal | 1m | Open items documented | [#48360](sample-tickets.md#L132) |

---

## Alert fatigue walkthrough (VPN storm)

During the **live** INC-2026-004 window, pfSense recorded **47 real `AUTH_FAILED` events** from `203.0.113.45`, which surfaced as multiple Sentinel alerts.

1. **Deduplication** — Group by source IP in Sentinel / `VPNLogs`
2. **Context** — 47 failures, 0 successes, invalid usernames → scanner noise
3. **Change management** — Matched **CHG-8821** (geo-block cutover)
4. **Action** — Parent ticket [#48322](sample-tickets.md#L86); bulk close
5. **Tuning** — [#48355](sample-tickets.md#L170) for `vpn-policy` suppression window

---

## Shift handoff (exercise)

Structured handoff example at **15:50 UTC** — [Ticket #48360](sample-tickets.md#L132):

```text
OPEN ITEMS FOR NEXT SHIFT
─────────────────────────
1. INC-2026-002 (closed) — jsmith password reset complete; temporary CA block on
   203.0.113.55 expired 2026-06-15 12:00 UTC. Confirmed auto-removal.
2. Ticket #48355 (open) — VPN rule tuning for CHG-8821 window.
3. Duplicate watch — WKSTN-042: INC-001 + INC-003 + INC-005 + INC-006 all closed;
   link parent tickets before re-isolating. Watch WKSTN-099 for RDP recurrence.
```