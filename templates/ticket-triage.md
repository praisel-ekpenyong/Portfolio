# Alert Triage Ticket Template

## Jira / ServiceNow Fields

| Field | Value |
|-------|-------|
| **Summary** | [P2] Wazuh 180001 — Suspicious BITS job on WKSTN-042 |
| **Queue** | SOC-Tier1 |
| **Priority** | P2 |
| **Category** | Malware / Suspicious Execution |
| **Assignee** | Praisel Ekpenyong (SOC Analyst L1) |
| **Linked Alerts** | Wazuh ID 2847192, Defender ALRT-99281 |

---

## Triage Checklist

- [ ] Alert acknowledged < 15 min
- [ ] Duplicate search (hostname + rule, 24 hr)
- [ ] Asset criticality confirmed in CMDB
- [ ] User/account identified
- [ ] MITRE technique noted
- [ ] IOC enrichment run (`ioc_enrichment.py`)
- [ ] SIEM query saved to ticket
- [ ] FP / TP / Inconclusive decision documented
- [ ] Escalation criteria evaluated (`docs/soc-playbooks.md`)

---

## Initial Investigation Notes

```
14:30 UTC — Opened ticket from Wazuh dashboard.
Host WKSTN-042 is finance workstation. No change tickets.
Sysmon shows bitsadmin /transfer to 10.10.30.10:8888.
Correlates with Caldera op 2026-06-17-INC001-BITS-LAB (lab).
Proceeding with host isolation per P2 playbook.
```

---

## SIEM Query (paste)

```spl
index=sysmon host=WKSTN-042 EventCode=1 CommandLine="*bitsadmin*"
```

---

## Resolution

| Outcome | Details |
|---------|---------|
| **True Positive** | Contained, eradicated, closed INC-2026-001 |
| **False Positive** | See INC-2026-004 for example closure |
| **Escalated** | Link parent IR ticket |

---

## Time Tracking

| Phase | Minutes |
|-------|---------|
| Triage | |
| Investigation | |
| Containment | |
| Documentation | |
| **Total** | |