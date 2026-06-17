# Incident Report Template

> Copy for each new incident. Link Caldera operation ID when applicable.

## Header

| Field | Value |
|-------|-------|
| Incident ID | INC-YYYY-### |
| osTicket | ###### |
| Analyst | Praisel Ekpenyong (SOC Analyst L1) |
| Contact | Ekpenyongpraisel@gmail.com |
| Severity | P1 / P2 / P3 / P4 / P5 |
| Status | Open / Contained / Closed |
| Detection Source | Wazuh / Splunk / Sentinel / MDE / User Report |
| Caldera Operation | (if lab validation) |
| MITRE ATT&CK | |

---

## 1. Detection

*What fired, when (UTC), and initial auto-assigned severity.*

## 2. Validation

| Check | Result |
|-------|--------|
| Change ticket / known activity? | |
| Legitimate user/admin action? | |
| Duplicate alert? | |
| True positive / False positive / Inconclusive | |

## 3. Enrichment

### Affected Assets

| Hostname | IP | Role | Criticality |
|----------|-----|------|-------------|
| | | | |

### Accounts

| Account | Type | Last logon | Risk |
|---------|------|------------|------|

### IOC Table

| IOC | Type | Enrichment | Verdict |
|-----|------|------------|---------|
| | IP / Domain / URL / Hash | | |

## 4. Containment

| Time (UTC) | Action | Analyst |
|------------|--------|---------|
| | | |

## 5. Eradication

| Time (UTC) | Action |
|------------|--------|
| | |

## 6. Recovery

| Time (UTC) | Action |
|------------|--------|
| | |

## 7. Escalation

- **Escalated?** Yes / No
- **To:** Tier 2 / IR / Management
- **Reason:**
- **Handoff artifacts:**

## 8. Timeline (UTC)

| Time | Event |
|------|-------|
| | |

## 9. Evidence

```
Paste relevant log lines, queries, screenshots references
```

## 10. Root Cause

## 11. Recommendations

1. Detection tuning
2. Hardening
3. Process / training

## 12. Sign-off

| Role | Name | Date |
|------|------|------|
| Tier 1 Analyst | Praisel Ekpenyong | |
| Tier 2 Reviewer | | |