# Sample SOC Tickets (osTicket)

osTicket records from the Tier 1 queue — **Department: Security Operations**.  
**Analyst:** Praisel Ekpenyong · SOC Analyst L1  
**Contact:** Ekpenyongpraisel@gmail.com · [GitHub](https://github.com/praisel-ekpenyong) · [LinkedIn](https://www.linkedin.com/in/praiselekpenyong)  
**Certs:** Google Cybersecurity Certificate · Security+ · SC-200

---

## Ticket #48291 — BITS Download (INC-2026-001)

| Field | Value |
|-------|-------|
| **Subject** | [High] Wazuh 180001 — Suspicious BITS job on WKSTN-042 |
| **Department** | Security Operations |
| **Help Topic** | Security Incident |
| **Priority** | High |
| **Status** | Closed |
| **Source** | API (Wazuh webhook) |
| **Created** | 2026-06-17 14:22 UTC |
| **Closed** | 2026-06-17 16:00 UTC |
| **Assigned To** | Praisel Ekpenyong |
| **Linked Incident** | INC-2026-001 |

**Internal note (14:30 UTC):** Wazuh rule 180001 fired on WKSTN-042 for bitsadmin transfer. Investigated Sysmon and Defender alerts. No matching change ticket. Proceeding with host isolation per playbook.

**Internal note (14:35 UTC):** Host isolated via Defender. Linked INC-2026-001. Escalated to Tier 2.

**Resolution (closed):** True positive (lab emulation). Payload quarantined. User password reset. Detection validated.

**Metrics:** Time to acknowledge — 8 min · Time to contain — 13 min

---

## Ticket #48305 — Linux Account Creation (INC-2026-002)

| Field | Value |
|-------|-------|
| **Subject** | [High] Unauthorized local account on SRV-LNX-01 |
| **Department** | Security Operations |
| **Help Topic** | Security Incident |
| **Priority** | High |
| **Status** | Closed |
| **Source** | API (Wazuh webhook) |
| **Assigned To** | Praisel Ekpenyong |
| **Linked Incident** | INC-2026-002 |

**Internal note:** Unauthorized user `caldera_svc` and malicious crontab on SRV-LNX-01. Wazuh rules 5902/2832.

**Resolution (closed):** Account deleted, cron restored, egress blocked during investigation. Escalated to Linux SME.

---

## Ticket #48318 — RDP Port Change (INC-2026-003)

| Field | Value |
|-------|-------|
| **Subject** | [High] Network sniffing and RDP port change on WKSTN-099 |
| **Department** | Security Operations |
| **Help Topic** | Security Incident |
| **Priority** | High |
| **Status** | Closed |
| **Source** | API (Wazuh webhook) |
| **Assigned To** | Praisel Ekpenyong |
| **Linked Incident** | INC-2026-003 |

**Internal note:** tshark execution and RDP registry modification on WKSTN-099 (finance segment). PCAP and pfSense logs reviewed.

**Resolution (closed):** No credential exfil in PCAP. RDP port restored. IR engaged per policy; closed after scope check.

---

## Ticket #48322 — VPN Auth Failures (INC-2026-004)

| Field | Value |
|-------|-------|
| **Subject** | [Normal] Multiple failed VPN logins — 203.0.113.45 |
| **Department** | Security Operations |
| **Help Topic** | Alert Triage |
| **Priority** | Normal → Low (downgraded) |
| **Status** | Closed |
| **Source** | API (Sentinel connector) |
| **Assigned To** | Praisel Ekpenyong |
| **Linked Incident** | INC-2026-004 |

**Internal note:** 47 failed VPN logins from external IP. Checked pfSense and change records.

**Resolution (closed — false positive):** External scanner noise after CHG-8821 geo-block. No internal users affected. Opened linked Ticket #48355 for detection tuning.

**Closure comment:** See INC-2026-004 section 6.

---

## Ticket #48340 — Phishing Report (INC-2026-005)

| Field | Value |
|-------|-------|
| **Subject** | [High] User-reported phishing — invoice attachment |
| **Department** | Security Operations |
| **Help Topic** | Security Incident |
| **Priority** | High |
| **Status** | Closed |
| **Source** | Email (user report) |
| **Assigned To** | Praisel Ekpenyong |
| **Linked Incident** | INC-2026-005 |

**Internal note:** jsmith reported invoice phish. SPF/DKIM/DMARC failed. Correlated with Sentinel PowerShell alert on WKSTN-042.

**Resolution (closed):** Contained WKSTN-042. Blocked domain. Mail trace clean for other users.

---

## Ticket #48355 — Detection Tuning (linked to #48322)

| Field | Value |
|-------|-------|
| **Subject** | [Low] Tune Sentinel VPN brute-force rule for change windows |
| **Department** | Security Operations |
| **Help Topic** | Detection Tuning |
| **Priority** | Low |
| **Status** | Open |
| **Source** | Web (analyst-created) |
| **Parent Ticket** | #48322 |
| **Assigned To** | Praisel Ekpenyong |

**Description:** Add 24-hour suppression to Sentinel rule `Multiple failed VPN logins` when change ticket tag `vpn-policy` is open.

**Acceptance criteria:** No High/Normal priority tickets from geo-block cutover test window.

---

## Ticket Hygiene Checklist (Tier 1 · osTicket)

1. Every incident gets an osTicket record + linked INC document
2. Paste SIEM query in an **internal note** (not the public thread)
3. Record UTC timestamps in notes for MTTA / MTTC metrics
4. Tag MITRE technique IDs in the subject or custom field
5. False positives get a **reason** in the closure note — not just "Closed"
6. Escalations: reassign to Tier 2 queue or link child ticket; attach escalation template
7. Use **Post Internal Note** for investigation; **Post Reply** only when contacting the reporter