# Sample SOC Tickets

Jira-style records demonstrating Tier 1 ticketing discipline across the portfolio.  
**Analyst:** Praisel Ekpenyong · SOC Analyst L1  
**Contact:** Ekpenyongpraisel@gmail.com · [GitHub](https://github.com/praisel-ekpenyong) · [LinkedIn](https://www.linkedin.com/in/praiselekpenyong)  
**Certs:** Google Cybersecurity Certificate · Security+ · SC-200

---

## SEC-48291 — BITS Download (INC-2026-001)

| Field | Value |
|-------|-------|
| Type | Incident |
| Priority | P2 |
| Status | **Resolved** |
| Created | 2026-06-17 14:22 UTC |
| Resolved | 2026-06-17 16:00 UTC |
| Assignee | Praisel Ekpenyong (SOC Analyst L1) |
| Labels | `caldera-lab`, `T1197`, `windows`, `wazuh` |

**Description:** Wazuh rule 180001 fired on WKSTN-042 for bitsadmin transfer. Investigated Sysmon and Defender alerts. Host isolated. Linked INC-2026-001.

**Resolution:** True positive (lab emulation). Payload quarantined. User password reset. Detection validated.

**Time to acknowledge:** 8 min  
**Time to contain:** 13 min

---

## SEC-48305 — Linux Account Creation (INC-2026-002)

| Field | Value |
|-------|-------|
| Type | Incident |
| Priority | P2 |
| Status | **Resolved** |
| Labels | `caldera-lab`, `T1136`, `linux` |
| Assignee | Praisel Ekpenyong (SOC Analyst L1) |

**Description:** Unauthorized user `caldera_svc` and malicious crontab on SRV-LNX-01.

**Resolution:** Account deleted, cron restored, egress blocked during investigation. Escalated to Linux SME.

---

## SEC-48318 — RDP Port Change (INC-2026-003)

| Field | Value |
|-------|-------|
| Type | Incident |
| Priority | P2 |
| Status | **Resolved** |
| Labels | `T1040`, `T1021.001`, `escalated-IR` |
| Assignee | Praisel Ekpenyong (SOC Analyst L1) |

**Description:** tshark execution and RDP registry modification on WKSTN-099.

**Resolution:** PCAP reviewed — no credential exfil. RDP port restored. IR engaged per policy; closed after scope check.

---

## SEC-48322 — VPN Auth Failures (INC-2026-004)

| Field | Value |
|-------|-------|
| Type | Alert |
| Priority | P3 → P5 |
| Status | **Closed — False Positive** |
| Labels | `vpn`, `false-positive`, `tuning-request` |
| Assignee | Praisel Ekpenyong (SOC Analyst L1) |

**Description:** 47 failed VPN logins from 203.0.113.45.

**Resolution:** External scanner noise after CHG-8821 geo-block. No internal users affected. Tuning request CHG-8822 opened.

**Closure comment:** See INC-2026-004 section 6.

---

## SEC-48340 — Phishing Report (INC-2026-005)

| Field | Value |
|-------|-------|
| Type | Incident |
| Priority | P2 |
| Status | **Resolved** |
| Source | User report + Sentinel |
| Labels | `phishing`, `T1566`, `caldera-lab` |
| Assignee | Praisel Ekpenyong (SOC Analyst L1) |

**Description:** jsmith reported invoice phish; correlated with PowerShell execution.

**Resolution:** Contained WKSTN-042. Blocked domain. Mail trace clean for other users.

---

## SEC-48355 — Detection Tuning (Child of SEC-48322)

| Field | Value |
|-------|-------|
| Type | Change Request |
| Priority | P4 |
| Status | **In Progress** |
| Parent | SEC-48322 |
| Assignee | Praisel Ekpenyong (SOC Analyst L1) |

**Description:** Add 24-hour suppression to Sentinel rule `Multiple failed VPN logins` when change ticket tag `vpn-policy` is open.

**Acceptance criteria:** No P3+ tickets from geo-block cutover test window.

---

## Ticket Hygiene Checklist (Tier 1)

1. Every incident gets parent ticket + linked INC document
2. Paste SIEM query in ticket body
3. Record UTC timestamps for MTTA / MTTC metrics
4. Tag MITRE technique IDs for reporting
5. False positives get **reason**, not just "closed"
6. Escalations link child ticket to IR queue item