# Simulated High-Volume Shift Triage & Metrics

> [!NOTE]
> **Compressed Pedagogical Shift:** This shift log is a simulated synthesis designed to model triage prioritization and alert fatigue management. The timestamps of individual incidents in their respective standalone reports (which span June 13–18) have been compressed here into a single chronological 8-hour shift narrative to demonstrate operational SOC workflow.

This document provides a cohesive shift and alert-fatigue management narrative, mapping out a simulated 8-hour shift on **June 17, 2026 (08:00 – 16:00 UTC)**. It shows how the core incidents in this lab environment interleave with background noise, how triage priorities were established, and how alert storms were tuned out.

---

## Lab Simulation Setup

Because this is an independent lab environment, this "shift" represents a compressed log playback and adversary emulation campaign designed to simulate a high-stress production environment:
1. **Adversary Emulation:** **Apache Caldera** operations (`T1-Phish-to-Host`, `T1-Windows-Download-Exec`, and `T1-Scheduled-Task`) were run autonomously targeting `WKSTN-042` to produce live, correlated endpoint alerts in Wazuh and Splunk.
2. **Identity Spray Simulation:** A custom PowerShell loop was executed to simulate an Entra ID password spray attack against the cloud tenant (`pe-soc-lab`).
3. **Log Playback (Noise):** Active Directory GPO updates, Defender signature checks, and a pfSense-logged external network scanner brute-forcing the VPN were replayed to generate high-volume background noise (representing alert fatigue).

---

## Shift Triage Metrics

These metrics quantify the performance of the triage run, modeling standard SOC Service Level Agreements (SLAs) and Key Performance Indicators (KPIs):

| Metric | Value | Definition / Operational Impact |
|--------|-------|---------------------------------|
| **Total Alerts Ingested** | 22 | Total alerts hitting the Tier 1 security queue. |
| **Mean Time to Acknowledge (MTTA)** | 3m 40s | Time from alert ingestion to the analyst assigning/opening the ticket. |
| **Mean Time to Contain (MTTC)** | 9m 45s | Time from acknowledgement to containment (e.g., host isolation, session revocation). |
| **False Positive Rate** | 63.6% | 14 out of 22 alerts were verified as benign noise, system updates, or scanning activity. |
| **Escalations to Tier 2** | 5 | True positive cases escalated to senior analysts with complete triage notes. |

---

## Triage Strategy & Prioritization

To prevent alert fatigue and protect critical assets, the following triage prioritization rules were applied during the shift:

1. **Severity 1 (Critical/High): User Reports & Auth Successes**
   * *Examples:* Phishing reports with attachments ([INC-2026-005](../incidents/INC-2026-005-phishing-chain.md)) or password sprays resulting in a successful logon ([INC-2026-002](../incidents/INC-2026-002-entra-password-spray.md)).
   * *Action:* Triage immediately. Isolate host/revoke credentials within 15 minutes of alert arrival.
2. **Severity 2 (Medium): High-Severity Endpoint Detections**
   * *Examples:* Wazuh alerts for BITSAdmin downloads ([INC-2026-001](../incidents/INC-2026-001-bits-job-download.md)) and non-standard scheduled tasks ([INC-2026-003](../incidents/INC-2026-003-scheduled-task-persistence.md)).
   * *Action:* Validate process parameters against baseline; isolate host if signatures match known LOLBin abuses.
3. **Severity 3 (Low): Perimeter Scanning & Authentication Noise**
   * *Examples:* Mass failed VPN logins from single IP blocks ([INC-2026-004](../incidents/INC-2026-004-false-positive-vpn.md)).
   * *Action:* Check internal Change Management (CHG) system first. Group and bulk-close as false positives if matched to maintenance windows.

---

## 22-Alert Chronological Shift Queue

The table below lists all alerts triaged during the simulated shift. Core lab incidents and tickets are linked directly.

| Time (UTC) | Source | Alert Summary / Rule Name | Priority | MTTA | Action Taken | Case / Ticket Link |
|------------|--------|---------------------------|----------|------|--------------|--------------------|
| **08:05** | Wazuh | Rule 1002 — Windows host login failure | Low | 1m | Verified local admin typo; closed as benign. | N/A |
| **08:12** | Wazuh | Rule 1002 — Windows host login failure | Low | 2m | Same host; closed. | N/A |
| **08:30** | Splunk | Defender Signature Update Complete | Info | 5m | Auto-closed; informational. | N/A |
| **09:00** | Sentinel | Entra ID password spray: jsmith@corp.lab | High | 2m | Spotted 18 failed sign-ins + 1 success. | [INC-2026-002](../incidents/INC-2026-002-entra-password-spray.md) · [Ticket #48305](sample-tickets.md#L36) |
| **09:05** | Sentinel | Entra ID risk score elevated: jsmith@corp.lab | High | 1m | Revoked user sessions, isolated WKSTN-042. | [INC-2026-002](../incidents/INC-2026-002-entra-password-spray.md) · [Ticket #48305](sample-tickets.md#L36) |
| **09:15** | Wazuh | Active Directory GPO refresh success | Info | 10m | Auto-closed; baseline noise. | N/A |
| **09:40** | Splunk | Firewall administrative interface logon | Normal | 3m | Checked change ticket CHG-8815; admin matched. | N/A |
| **10:10** | Sentinel | Multiple failed VPN logins — 203.0.113.45 | Normal | 4m | Alert storm starts (47 failed auths). | [INC-2026-004](../incidents/INC-2026-004-false-positive-vpn.md) · [Ticket #48322](sample-tickets.md#L86) |
| **10:15** | Sentinel | VPN brute force threshold breached | Normal | 2m | Correlated with CHG-8821 (geo-block cutover). | [INC-2026-004](../incidents/INC-2026-004-false-positive-vpn.md) · [Ticket #48322](sample-tickets.md#L86) |
| **10:45** | Wazuh | Rule 1002 — Windows host login failure | Low | 4m | Benign dev server test; closed. | N/A |
| **11:30** | Splunk | SCCM software package scan initiated | Info | 8m | Auto-closed; scheduled activity. | N/A |
| **12:15** | User | Phishing report — Invoice attachment | High | 4m | Analyzed SPF/DKIM/DMARC failure on mail. | [INC-2026-005](../incidents/INC-2026-005-phishing-chain.md) · [Ticket #48340](sample-tickets.md#L109) |
| **12:22** | Sentinel | PowerShell execution payload download | High | 1m | Correlated click on WKSTN-042; isolated host. | [INC-2026-005](../incidents/INC-2026-005-phishing-chain.md) · [Ticket #48340](sample-tickets.md#L109) |
| **13:00** | Wazuh | Rule 180001 — Suspicious BITS job on WKSTN-042 | High | 6m | Verified BITSAdmin transfer command line. | [INC-2026-001](../incidents/INC-2026-001-bits-job-download.md) · [Ticket #48291](sample-tickets.md#L11) |
| **13:08** | Splunk | Sysmon Event ID 11 — Payload written to disk | High | 2m | Traced payload back to the initial phishing click. | [INC-2026-001](../incidents/INC-2026-001-bits-job-download.md) · [Ticket #48291](sample-tickets.md#L11) |
| **13:45** | Wazuh | Active Directory service account query | Low | 5m | Checked standard LDAP query; closed. | N/A |
| **14:10** | Wazuh | Rule 180002 — Task ChromeUpdate on WKSTN-042 | High | 3m | Checked task scheduler XML; creator is cmd. | [INC-2026-003](../incidents/INC-2026-003-scheduled-task-persistence.md) · [Ticket #48318](sample-tickets.md#L61) |
| **14:30** | Splunk | Sysmon Event 1 — cmd.exe executing update.ps1 | High | 2m | Confirmed unauthorized persistence; deleted task. | [INC-2026-003](../incidents/INC-2026-003-scheduled-task-persistence.md) · [Ticket #48318](sample-tickets.md#L61) |
| **14:40** | Wazuh | Rule 180003 — RDP port change on WKSTN-099 | High | 2m | Isolated host, initiated port revert. | [INC-2026-006](../incidents/INC-2026-006-rdp-lateral-movement.md) · [Ticket #48370](sample-tickets.md#L129) |
| **14:45** | Wazuh | Rule 180004 — Sniffer tcpdump.exe executed on WKSTN-099 | High | 1m | Isolated source WKSTN-042, revoked jsmith tokens. | [INC-2026-006](../incidents/INC-2026-006-rdp-lateral-movement.md) · [Ticket #48370](sample-tickets.md#L129) |
| **15:15** | Wazuh | Rule 1002 — Windows host login failure | Low | 4m | Benign noise; closed. | N/A |
| **15:50** | User | Shift Handoff ticket created | Normal | 1m | Documented open items and watchlists. | [Ticket #48360](sample-tickets.md#L132) |

---

## Alert Fatigue Walkthrough (VPN Storm)

Between **10:10 and 10:45 UTC**, the security queue was hit by an alert storm consisting of 47 individual authentication failure alerts originating from external IP `203.0.113.45` targeting our VPN gateway.

Instead of handling each alert as a separate investigation:
1. **Deduplication:** A KQL query in Microsoft Sentinel grouped the alerts by source IP:
   ```kql
   SigninLogs
   | where TimeGenerated >= datetime(2026-06-17 10:00:00)
   | where IPAddress == "203.0.113.45"
   | summarize FailureCount = count(), UsersTargeted = dcount(UserPrincipalName) by ResultType
   ```
2. **Context Checking:** The query showed 47 failures and 0 successful logins across 12 fake user accounts. This pointed to external scanning rather than credential stuffing.
3. **Change Management Check:** Cross-referenced our change management queue and matched the activity to **CHG-8821** (planned geo-blocking cutover and external testing window).
4. **Action:** Closed all 47 alerts as a single **False Positive** under parent [Ticket #48322](sample-tickets.md#L86) to prevent queue clutter.
5. **Tuning:** Opened [Ticket #48355](sample-tickets.md#L170) to tune the VPN detection rule, adding a temporary suppression policy for planned network testing windows to eliminate future alert storms.

---

## Simulated Shift Handoff

At the end of the shift (**15:50 UTC**), a structured handoff note was posted in osTicket under [Ticket #48360](sample-tickets.md#L132) to ensure a clean transition:

```text
OPEN ITEMS FOR NEXT SHIFT
─────────────────────────
1. INC-2026-002 (closed) — jsmith password reset complete; temporary CA block on
   203.0.113.55 expired 2026-06-15 12:00 UTC. Confirmed auto-removal.
2. Ticket #48355 (open) — VPN rule tuning for CHG-8821 window. No action tonight
   unless VPN High alerts fire again.
3. Duplicate watch — WKSTN-042: INC-001 + INC-003 + INC-005 + INC-006 all closed; if new alerts on
   same host, link parent tickets #48291 / #48318 / #48340 / #48370 before re-isolating.
   Check WKSTN-099 (INC-006) for RDP recurrence.

QUERIES IN PROGRESS
───────────────────
None — all P2 cases closed.

ESCALATIONS PENDING CALLBACK
────────────────────────────
None.
```
This structured approach prevents oncoming analysts from duplicating triage efforts on `WKSTN-042` and tracks pending policy tuning actions.
