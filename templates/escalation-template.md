# Tier 1 → Tier 2 / IR Escalation Handoff

## Escalation Request

| Field | Value |
|-------|-------|
| **From** | Praisel Ekpenyong (SOC Analyst L1) |
| **To** | Tier 2 / Incident Response |
| **Incident ID** | |
| **Ticket** | |
| **Escalation Time (UTC)** | |
| **Requested SLA** | 30 min callback for P2 |

---

## Executive Summary (2–3 sentences)

> Confirmed unauthorized code execution on WKSTN-042 via BITS download from external IP.
> Host isolated. Single user account. No lateral movement observed in first hour.

---

## Why Escalating

- [ ] Confirmed malware / C2
- [ ] Server or privileged asset involved
- [ ] Multiple hosts same IOC
- [ ] Domain Admin / service account anomaly
- [ ] Data exfiltration indicators
- [ ] Tier 1 lacks authority to (isolate DC / disable svc account / block C-suite device)
- [ ] Policy-mandated IR notification (e.g., packet capture on regulated data host)

---

## What Tier 1 Already Did

| Action | Time (UTC) |
|--------|------------|
| Alert validated | |
| IOC enrichment | |
| Host isolated | |
| Evidence exported | |
| User/password action | |

---

## Key Evidence

### IOCs

| IOC | Context |
|-----|---------|
| | |

### Timeline (UTC)

| Time | Event |
|------|-------|
| | |

### Queries / Screenshots

- Splunk saved search: `SOC-INC001-bitsadmin`
- EDR alert link: `(paste)`
- Caldera op ID (lab): `(paste)`

---

## Affected Assets

| Asset | Criticality | Status |
|-------|-------------|--------|
| | | Isolated / Monitoring / Unknown |

---

## Open Questions for Tier 2

1. Full disk forensics required?
2. Scope expansion hunt — same URL across fleet?
3. User interview needed before account re-enable?

---

## Contact

Analyst on shift: Praisel Ekpenyong  
Email: Ekpenyongpraisel@gmail.com