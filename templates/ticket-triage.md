# Alert Triage Ticket Template (osTicket)

## Ticket Fields

| Field | Value |
|-------|-------|
| **Subject** | [P2] Wazuh 180001 — Suspicious BITS job on WKSTN-042 |
| **Department** | Security Operations |
| **Help Topic** | Security Incident |
| **Priority** | High |
| **Status** | Open |
| **Source** | API / Email / Web |
| **Assigned To** | Praisel Ekpenyong (SOC Analyst L1) |
| **Linked Alerts** | Wazuh ID 2847192, Defender ALRT-99281 |

---

## Triage Checklist

- [ ] Ticket acknowledged < 15 min
- [ ] Duplicate search (hostname + rule, 24 hr)
- [ ] Asset criticality confirmed in CMDB
- [ ] User/account identified
- [ ] MITRE technique noted in subject or internal note
- [ ] IOC enrichment run (`ioc_enrichment.py`)
- [ ] SIEM query pasted in **internal note**
- [ ] FP / TP / Inconclusive decision documented
- [ ] Escalation criteria evaluated (`docs/soc-playbooks.md`)

---

## Internal Note (Post Internal Note — staff only)

```
14:30 UTC — Opened osTicket #48291 from Wazuh dashboard.
Host WKSTN-042 is finance workstation. No change tickets.
Sysmon shows bitsadmin /transfer to 10.10.30.10:8888.
Correlates with Caldera op 2026-06-13-INC001-BITS-LAB (lab).
Proceeding with host isolation per P2 playbook.
```

---

## SIEM Query (paste in internal note)

```spl
index=sysmon host=WKSTN-042 EventCode=1 CommandLine="*bitsadmin*"
```

---

## Resolution

| Outcome | osTicket action |
|---------|-----------------|
| **True Positive** | Close ticket — link INC document, set resolution note |
| **False Positive** | Close ticket — document reason (see INC-2026-004) |
| **Escalated** | Reassign to Tier 2 / IR · link parent ticket · attach `escalation-template.md` |

---

## Time Tracking (internal note)

| Phase | Minutes |
|-------|---------|
| Triage | |
| Investigation | |
| Containment | |
| Documentation | |
| **Total** | |